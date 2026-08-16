<?php
/**
 * Enquiry endpoint for Top Focus Medicare Limited.
 *
 * Accepts a JSON POST from the website contact form, validates it, runs a
 * lexicon-based sentiment analysis on the message, stores the enquiry to a
 * protected data file, and routes the follow-up based on the preferred means
 * of communication:
 *   - WhatsApp  -> returns a wa.me deep link so the user can message the clinic
 *   - Phone call -> initialises a callback request (stored + flagged for staff)
 *   - Email      -> always on; distinct bidirectional emails to user and admin
 *
 * Configuration via environment variables (set in the Alwaysdata account or
 * deployment secrets):
 *   CLINIC_EMAILS    - comma-separated inboxes that receive admin/platform
 *                      notifications (default admin@ & info@ ...com.ng)
 *   CLINIC_WHATSAPP  - clinic WhatsApp number in international format, digits
 *                      only, e.g. 2348012345678 (replace the placeholder below)
 *   MAIL_FROM        - From: address for outgoing mail (default no-reply@...com.ng)
 *   ALLOWED_ORIGINS  - comma-separated origins permitted by CORS (default the
 *                      clinic domains, https only)
 *
 * Security notes:
 *   - All header-bound user input is stripped of CR/LF and control chars to
 *     prevent email header injection.
 *   - CORS is restricted to an allowlist (no wildcard).
 *   - Per-IP file-based rate limiting guards against abuse/relaying.
 *   - PII is stored above the web root with 0600 file / 0700 directory perms.
 */

declare(strict_types=1);

// Fail closed in production: never leak stack traces or path details.
error_reporting(E_ALL);
@ini_set('display_errors', '0');
@ini_set('log_errors', '1');

/* ----------------------------- config ------------------------------------ */
const SITE_NAME = 'Top Focus Medicare Limited';
// All admin/platform emails are delivered to both inboxes.
const DEFAULT_CLINIC_EMAILS = 'admin@topfocusmedicareltd.com.ng,info@topfocusmedicareltd.com.ng';
const DEFAULT_MAIL_FROM = 'no-reply@topfocusmedicareltd.com.ng';
// TODO: replace with the real clinic WhatsApp number or set CLINIC_WHATSAPP.
const DEFAULT_CLINIC_WHATSAPP = '2348000000000';
const DEFAULT_ALLOWED_ORIGINS = 'https://topfocusmedicareltd.com.ng,https://www.topfocusmedicareltd.com.ng';

const MAX_INPUT_BYTES = 20480;     // reject request bodies larger than 20 KB
const RATE_LIMIT_WINDOW = 600;     // 10 minutes
const RATE_LIMIT_MAX = 5;          // max submissions per IP per window

$clinicEmails = array_values(array_filter(array_map('trim', explode(',', (string)(getenv('CLINIC_EMAILS') ?: DEFAULT_CLINIC_EMAILS)))));
$mailFrom = getenv('MAIL_FROM') ?: DEFAULT_MAIL_FROM;
$clinicWhatsapp = preg_replace('/\D+/', '', (string)(getenv('CLINIC_WHATSAPP') ?: DEFAULT_CLINIC_WHATSAPP));
$allowedOrigins = array_values(array_filter(array_map('trim', explode(',', (string)(getenv('ALLOWED_ORIGINS') ?: DEFAULT_ALLOWED_ORIGINS)))));

/* --------------------------- helpers ------------------------------------- */
function respond(int $code, bool $ok, string $message, array $extra = []): void
{
    http_response_code($code);
    echo json_encode(array_merge(['ok' => $ok, 'message' => $message], $extra), JSON_UNESCAPED_UNICODE);
    exit;
}

/** Multibyte-safe string length with a fallback when mbstring is absent. */
function safeStrlen(string $s): int
{
    return function_exists('mb_strlen') ? mb_strlen($s) : strlen($s);
}

/**
 * Strip CR, LF, NUL and other C0 control chars from a value. Any field that
 * is placed into an email header (name, email, phone, subject) must be passed
 * through this to prevent header injection (CRLF smuggling).
 */
function sanitizeHeaderField(string $s): string
{
    return str_replace(["\r", "\n", "\0"], '', preg_replace('/[\x00-\x1F\x7F]/', '', $s));
}

/** Resolve the originating client IP. REMOTE_ADDR is trusted over spoofable headers. */
function clientIp(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/* --------------------------- rate limiting ------------------------------- */
/**
 * Simple file-based per-IP throttle. Keeps a list of recent submission
 * timestamps and rejects requests that exceed RATE_LIMIT_MAX within the window.
 * Returns true when allowed, false when throttled.
 */
function rateLimitOk(string $ip, string $dir): bool
{
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
        // If we cannot persist a limit, fail open (do not block legitimate use).
        return true;
    }
    $file = $dir . '/' . hash('sha1', $ip) . '.json';
    $now = time();
    $fp = @fopen($file, 'c+');
    if (!$fp) {
        return true;
    }
    flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $times = $raw ? (json_decode($raw, true) ?: []) : [];
    if (!is_array($times)) {
        $times = [];
    }
    // Drop timestamps outside the window.
    $times = array_values(array_filter($times, fn($t) => is_int($t) && ($now - $t) < RATE_LIMIT_WINDOW));
    $allowed = count($times) < RATE_LIMIT_MAX;
    if ($allowed) {
        $times[] = $now;
        rewind($fp);
        ftruncate($fp, 0);
        fwrite($fp, json_encode($times));
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    @chmod($file, 0600);
    return $allowed;
}

/* --------------------------- sentiment analysis -------------------------- */
/**
 * Lightweight lexicon-based sentiment analysis. Returns a label and integer
 * score. Negation flips the polarity of the following word. No external
 * services or API keys required.
 */
function analyzeSentiment(string $text): array
{
    $positive = [
        'good', 'great', 'excellent', 'wonderful', 'amazing', 'thanks', 'thank',
        'grateful', 'happy', 'pleased', 'hopeful', 'kind', 'caring', 'comfortable',
        'helpful', 'professional', 'reassuring', 'confident', 'better', 'best',
        'love', 'appreciate', 'recommend', 'satisfied', 'polite', 'friendly',
        'calm', 'safe', 'trust', 'improved', 'clear', 'quick', 'prompt',
    ];
    $negative = [
        'bad', 'terrible', 'awful', 'pain', 'painful', 'worried', 'anxious',
        'scared', 'afraid', 'emergency', 'urgent', 'bleeding', 'fever', 'sick', 'ill',
        'worse', 'worst', 'sad', 'angry', 'frustrated', 'disappointed', 'rude', 'slow',
        'delay', 'delayed', 'problem', 'issue', 'concern', 'concerned', 'fear', 'died',
        'death', 'suffering', 'severe', 'chronic', 'infection', 'complication',
    ];

    $lower = function_exists('mb_strtolower') ? mb_strtolower(trim($text)) : strtolower(trim($text));
    $tokens = preg_split('/\s+/', $lower);
    $tokens = $tokens === false ? [] : array_values(array_filter($tokens, fn($t) => $t !== ''));

    $score = 0;
    $hits = ['positive' => 0, 'negative' => 0];
    $negators = ['not', 'no', 'never', "don't", "doesn't", "didn't", "isn't", "aren't", "wasn't", "weren't", 'without'];

    foreach ($tokens as $i => $word) {
        $clean = trim($word, ".,!?;:\"'()");
        $negated = $i > 0 && in_array(trim($tokens[$i - 1], ".,!?;:\"'()"), $negators, true);
        if (in_array($clean, $positive, true)) {
            $score += $negated ? -1 : 1;
            $hits[$negated ? 'negative' : 'positive']++;
        } elseif (in_array($clean, $negative, true)) {
            $score += $negated ? 1 : -1;
            $hits[$negated ? 'positive' : 'negative']++;
        }
    }

    $label = $score > 0 ? 'positive' : ($score < 0 ? 'negative' : 'neutral');
    return ['label' => $label, 'score' => $score, 'positive_hits' => $hits['positive'], 'negative_hits' => $hits['negative'], 'method' => 'lexicon'];
}

/* ------------------------------ CORS + headers --------------------------- */
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
// Reflect the Origin only if it is on the allowlist; otherwise emit no ACAO.
if ($origin !== '' && in_array($origin, $allowedOrigins, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Accept');
header('Access-Control-Max-Age: 600');

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
// HSTS: enforce HTTPS for 6 months on this origin (safe behind Alwaysdata TLS).
header('Strict-Transport-Security: max-age=15768000; includeSubDomains');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'message' => 'Method not allowed.']);
    exit;
}

/* ------------------------------ rate limit -------------------------------- */
$privateDir = __DIR__ . '/../private';
if (!rateLimitOk(clientIp(), $privateDir . '/ratelimit')) {
    header('Retry-After: ' . RATE_LIMIT_WINDOW);
    respond(429, false, 'Too many enquiries from your location. Please try again later.');
}

/* ------------------------------ input ------------------------------------ */
$raw = file_get_contents('php://input');
if ($raw === false || strlen($raw) > MAX_INPUT_BYTES) {
    respond(413, false, 'Request payload too large.');
}
$data = json_decode($raw, true);
if (!is_array($data)) {
    if (!empty($_POST)) {
        $data = $_POST;
    } else {
        respond(400, false, 'Invalid request payload.');
    }
}

// Honeypot: a hidden "company" field that humans leave blank.
if (!empty($data['company'])) {
    respond(200, true, 'Thank you. Your enquiry has been received.');
}

// Header-bound fields are sanitized to block CRLF/header injection.
$name = sanitizeHeaderField(trim((string)($data['name'] ?? '')));
$email = sanitizeHeaderField(trim((string)($data['email'] ?? '')));
$phone = sanitizeHeaderField(trim((string)($data['phone'] ?? '')));
$message = trim((string)($data['message'] ?? ''));

$services = $data['services'] ?? [];
$services = is_array($services) ? $services : [$services];
$services = array_values(array_filter(array_map('strval', $services), fn($v) => $v !== ''));

$contactMethod = $data['contact_method'] ?? [];
$contactMethod = is_array($contactMethod) ? $contactMethod : [$contactMethod];
$contactMethod = array_values(array_filter(array_map('strval', $contactMethod), fn($v) => $v !== ''));

/* ----------------------------- validation -------------------------------- */
$errors = [];
if ($name === '' || safeStrlen($name) > 120) {
    $errors[] = 'a valid name';
}
if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'a valid email address';
}
if ($message === '' || safeStrlen($message) > 5000) {
    $errors[] = 'a message';
}

$allowedServices = [
    'General Healthcare', 'Maternity Care', 'Infertility Care',
    'Obstetrics', 'Surgical Management', 'Diagnostics & Laboratory',
];
$services = array_values(array_intersect($services, $allowedServices));

$allowedMethods = ['WhatsApp', 'Phone call', 'Email'];
$contactMethod = array_values(array_intersect($contactMethod, $allowedMethods));

if (in_array('WhatsApp', $contactMethod, true) || in_array('Phone call', $contactMethod, true)) {
    if ($phone === '' || strlen(preg_replace('/[^0-9+]/', '', $phone)) < 7) {
        $errors[] = 'a valid phone number for WhatsApp/Phone call';
    }
}
if ($errors) {
    respond(422, false, 'Please provide ' . implode(', ', $errors) . '.');
}

/* --------------------- sentiment + routing decisions -------------------- */
$sentiment = analyzeSentiment($message);

$wantsWhatsapp = in_array('WhatsApp', $contactMethod, true);
$wantsCall = in_array('Phone call', $contactMethod, true);
$wantsEmail = in_array('Email', $contactMethod, true);
// Email confirmation is always sent to the user regardless of preference.
$sendUserEmail = $email !== '';

// Build a WhatsApp deep link when requested and a clinic number is configured.
$whatsappLink = null;
if ($wantsWhatsapp && $clinicWhatsapp !== '') {
    $waText = "Hello Top Focus Medicare, my name is {$name}.";
    if ($services) {
        $waText .= " I'm interested in: " . implode(', ', $services) . ".";
    }
    $waText .= " (Ref: pending)\n\n" . $message;
    $whatsappLink = 'https://wa.me/' . $clinicWhatsapp . '?text=' . rawurlencode($waText);
}

// Initialise a callback request when Phone call is selected.
$callbackRequested = $wantsCall;

/* ------------------------------ persistence ------------------------------ */
$record = [
    'id' => bin2hex(random_bytes(8)),
    'received_at' => date('c'),
    'ip' => clientIp(),
    'name' => $name,
    'email' => $email,
    'phone' => $phone,
    'services' => $services,
    'contact_method' => $contactMethod,
    'message' => $message,
    'sentiment' => $sentiment,
    'callback_requested' => $callbackRequested,
    'whatsapp_link' => $whatsappLink,
];

if (!is_dir($privateDir)) {
    @mkdir($privateDir, 0700, true);
}

/**
 * Append a JSON line to a protected file with an exclusive lock and tighten
 * permissions. Returns success so the endpoint can fail loudly if an enquiry
 * cannot be stored.
 */
function appendRecord(string $file, string $line): bool
{
    $ok = (bool)@file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
    if ($ok) {
        @chmod($file, 0600);
    }
    return $ok;
}

$stored = appendRecord($privateDir . '/enquiries.jsonl', json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
if (!$stored) {
    respond(500, false, 'We could not store your enquiry. Please try again or call us.');
}

// Separate callback queue for staff to action phone call-backs.
if ($callbackRequested) {
    $callback = [
        'id' => $record['id'],
        'requested_at' => $record['received_at'],
        'name' => $name,
        'phone' => $phone,
        'services' => $services,
        'message' => $message,
        'sentiment' => $sentiment['label'],
        'status' => 'pending',
    ];
    appendRecord($privateDir . '/callbacks.jsonl', json_encode($callback, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
}

/* --------------------- bidirectional email dispatch ---------------------- */
$userEmailSent = false;
$adminEmailSent = 0;
$servicesList = $services ? implode(', ', $services) : 'None selected';
$methodList = $contactMethod ? implode(', ', $contactMethod) : 'None selected';

// mailFrom is header-bound, so sanitize defensively even though it is config.
$safeMailFrom = sanitizeHeaderField($mailFrom);

// --- Admin notification (all clinic inboxes) ---
$adminSubject = sprintf('[%s] New enquiry from %s (%s)', strtoupper($sentiment['label']), $name, $record['id']);
$adminBody = "New enquiry received via the website.\n\n"
    . "Reference: {$record['id']}\n"
    . "Received: {$record['received_at']}\n"
    . "Sentiment: {$sentiment['label']} (score {$sentiment['score']}; +{$sentiment['positive_hits']}/-{$sentiment['negative_hits']})\n\n"
    . "Name: {$name}\n"
    . "Email: {$email}\n"
    . "Phone: {$phone}\n"
    . "Services: {$servicesList}\n"
    . "Preferred contact: {$methodList}\n"
    . "Callback requested: " . ($callbackRequested ? 'YES — call the patient back ASAP' : 'no') . "\n\n"
    . "Message:\n{$message}\n";
if ($whatsappLink) {
    $adminBody .= "\nWhatsApp chat link (patient will also receive this): {$whatsappLink}\n";
}
// adminSubject is header-bound; strip any stray control chars.
$adminSubject = sanitizeHeaderField($adminSubject);
$adminHeaders = "From: " . SITE_NAME . " <{$safeMailFrom}>\r\n"
    . "Reply-To: {$name} <{$email}>\r\n"
    . "Content-Type: text/plain; charset=utf-8\r\n";
if (function_exists('mail')) {
    foreach ($clinicEmails as $inbox) {
        $inbox = sanitizeHeaderField($inbox);
        if ($inbox !== '' && filter_var($inbox, FILTER_VALIDATE_EMAIL)) {
            if (@mail($inbox, $adminSubject, $adminBody, $adminHeaders)) {
                $adminEmailSent++;
            }
        }
    }
}

// --- User confirmation (auto-reply, distinct content) ---
if ($sendUserEmail) {
    $firstName = explode(' ', $name)[0];
    $userSubject = 'We received your enquiry — ' . SITE_NAME;
    $userBody = "Hi {$firstName},\n\n"
        . "Thank you for reaching out to " . SITE_NAME . ". We have received your enquiry and our care team will follow up shortly.\n\n"
        . "Your reference: {$record['id']}\n"
        . "Services you asked about: {$servicesList}\n\n";
    if ($wantsWhatsapp && $whatsappLink) {
        $userBody .= "You asked to be contacted on WhatsApp. Tap the link below to start the conversation with us now:\n"
            . "{$whatsappLink}\n\n";
    }
    if ($wantsCall) {
        $userBody .= "You requested a phone call. A member of our team will call you back on {$phone} as soon as possible.\n\n";
    }
    if ($wantsEmail) {
        $userBody .= "You'll also receive further updates by email.\n\n";
    }
    $userBody .= "Your message to us:\n\"{$message}\"\n\n"
        . "If you did not submit this enquiry, please ignore this email.\n\n"
        . "Caring for you,\n"
        . SITE_NAME . "\n";
    $userSubject = sanitizeHeaderField($userSubject);
    $userHeaders = "From: " . SITE_NAME . " <{$safeMailFrom}>\r\n"
        . "Reply-To: " . sanitizeHeaderField($clinicEmails[0] ?? '') . "\r\n"
        . "Content-Type: text/plain; charset=utf-8\r\n";
    if (function_exists('mail')) {
        $userEmailSent = @mail($email, $userSubject, $userBody, $userHeaders);
    }
}

/* ------------------------------ response --------------------------------- */
$nextSteps = [
    'whatsapp_link' => $whatsappLink,
    'callback_requested' => $callbackRequested,
    'phone' => $callbackRequested ? $phone : null,
    'email_sent_to_user' => $userEmailSent,
    'email_sent_to_admin' => $adminEmailSent > 0,
    'admin_recipients' => $adminEmailSent,
];

respond(
    200,
    true,
    'Thank you. Your enquiry has been received. We will reach out shortly.',
    [
        'reference' => $record['id'],
        'sentiment' => $sentiment,
        'next_steps' => $nextSteps,
    ]
);
