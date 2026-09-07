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
// Public base URL of the deployed site — used for the hosted logo in branded emails.
const DEFAULT_BASE_URL = 'https://topfocusmedicareltd.com.ng';

const MAX_INPUT_BYTES = 20480;     // reject request bodies larger than 20 KB
// Multi-dimensional rate limiting (sliding-window, file-based, atomic).
const RATE_LIMIT_WINDOW = 600;     // seconds — applies to all dimensions
const RATE_LIMIT_IP_MAX = 5;       // per-IP submissions per window (primary)
const RATE_LIMIT_EMAIL_MAX = 3;    // per-(hashed)email submissions per window (anti-relay)
const RATE_LIMIT_GLOBAL_MAX = 60;  // total submissions per window (circuit breaker for distributed floods)
// Stale-bucket garbage collection to bound inode usage.
const RATE_LIMIT_GC_PROBABILITY = 0.02;  // chance to run GC on any request
const RATE_LIMIT_GC_THRESHOLD = 1000;   // also run GC when bucket file count exceeds this

$clinicEmails = array_values(array_filter(array_map('trim', explode(',', (string)(getenv('CLINIC_EMAILS') ?: DEFAULT_CLINIC_EMAILS)))));
$mailFrom = getenv('MAIL_FROM') ?: DEFAULT_MAIL_FROM;
$clinicWhatsapp = preg_replace('/\D+/', '', (string)(getenv('CLINIC_WHATSAPP') ?: DEFAULT_CLINIC_WHATSAPP));
$allowedOrigins = array_values(array_filter(array_map('trim', explode(',', (string)(getenv('ALLOWED_ORIGINS') ?: DEFAULT_ALLOWED_ORIGINS)))));
// Normalise the base URL (no trailing slash) for building absolute asset URLs.
$baseUrl = rtrim((string)(getenv('BASE_URL') ?: DEFAULT_BASE_URL), '/');

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
 * Robust, file-based, multi-dimensional rate limiter.
 *
 * Design goals (no external store such as Redis — pure filesystem, secure):
 *  - Multi-dimensional: per-IP (primary), per-email (anti-relay), global
 *    (circuit breaker against distributed floods).
 *  - Sliding-window counters via a small, space-bounded list of timestamps.
 *  - Atomic updates under an exclusive file lock (no race conditions).
 *  - Privacy: bucket keys are hashed (sha256) so raw IPs/emails are never
 *    stored in cleartext filenames; files are 0600, the bucket dir is 0700.
 *  - Bounded disk usage: each bucket stores at most `max` timestamps, and a
 *    probabilistic garbage collector prunes stale bucket files.
 *  - Observability: emits IETF RateLimit-* response headers + Retry-After.
 *  - Availability: fails open (allows the request) only when the store is
 *    genuinely unavailable, logging the failure — never blocks legit users on
 *    a transient disk error, while the global cap still backstops abuse.
 */
final class RateLimiter
{
    private string $dir;

    public function __construct(string $dir)
    {
        $this->dir = $dir;
    }

    /**
     * Attempt to consume one unit for a bucket. Returns a result array:
     *   ['allowed' => bool, 'remaining' => int, 'reset' => int (seconds to window reset)]
     * On a store error, fails open with allowed=true (and logs).
     */
    public function attempt(string $bucketKey, int $max, int $window): array
    {
        if (!$this->ensureDir()) {
            error_log('RateLimiter: store unavailable, failing open');
            return ['allowed' => true, 'remaining' => $max, 'reset' => $window];
        }
        $this->maybeGc($window);

        $file = $this->dir . '/' . hash('sha256', $bucketKey) . '.json';
        $now = time();
        $fp = @fopen($file, 'c+');
        if (!$fp) {
            error_log('RateLimiter: cannot open bucket, failing open');
            return ['allowed' => true, 'remaining' => $max, 'reset' => $window];
        }
        flock($fp, LOCK_EX);
        try {
            $raw = stream_get_contents($fp);
            $times = $raw ? (json_decode($raw, true) ?: []) : [];
            if (!is_array($times)) {
                $times = [];
            }
            // Sliding window: keep only timestamps within the window.
            $times = array_values(array_filter($times, fn($t) => is_int($t) && ($now - $t) < $window));
            $allowed = count($times) < $max;
            if ($allowed) {
                $times[] = $now;
                // Bound storage to the last `max` timestamps.
                if (count($times) > $max) {
                    $times = array_slice($times, -$max);
                }
                rewind($fp);
                ftruncate($fp, 0);
                fwrite($fp, json_encode($times));
            }
            $remaining = max(0, $max - count($times));
            // Reset = seconds until the oldest timestamp in the window ages out.
            $reset = $times ? max(1, $window - ($now - $times[0])) : $window;
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
            @chmod($file, 0600);
        }
        return ['allowed' => $allowed, 'remaining' => $remaining, 'reset' => $reset];
    }

    private function ensureDir(): bool
    {
        if (is_dir($this->dir)) {
            return true;
        }
        $ok = @mkdir($this->dir, 0700, true);
        // Defensive: mkdir's mode is masked by umask and the parent's setgid bit,
        // so explicitly enforce the intended permissions regardless of the
        // environment. Best-effort — ignore if it cannot be changed.
        if ($ok) {
            @chmod($this->dir, 0700);
        }
        return $ok;
    }

    /**
     * Prune stale bucket files to bound inode usage. Runs with low probability
     * or when the bucket count exceeds the threshold. Best-effort and locked
     * per file; never throws.
     */
    private function maybeGc(int $window): void
    {
        $run = (mt_rand() / mt_getrandmax()) < RATE_LIMIT_GC_PROBABILITY;
        if (!$run) {
            // Cheap count via glob (no directory scan cost beyond listing names).
            $count = count(glob($this->dir . '/*.json'));
            if ($count < RATE_LIMIT_GC_THRESHOLD) {
                return;
            }
        }
        $cutoff = time() - $window;
        foreach (glob($this->dir . '/*.json') as $f) {
            if (@filemtime($f) < $cutoff) {
                @unlink($f);
            }
        }
    }
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
$limiter = new RateLimiter($privateDir . '/ratelimit');

// Primary dimension: per-IP (cheap path, runs before input parsing).
$ipResult = $limiter->attempt('ip:' . clientIp(), RATE_LIMIT_IP_MAX, RATE_LIMIT_WINDOW);
// Circuit breaker: global cap protects against distributed floods regardless of IP.
$globalResult = $limiter->attempt('global', RATE_LIMIT_GLOBAL_MAX, RATE_LIMIT_WINDOW);
if (!$ipResult['allowed'] || !$globalResult['allowed']) {
    $retryAfter = max($ipResult['reset'], $globalResult['reset']);
    header('Retry-After: ' . $retryAfter);
    header('RateLimit-Policy: ' . RATE_LIMIT_IP_MAX . ';w=' . RATE_LIMIT_WINDOW);
    $remaining = min($ipResult['remaining'], $globalResult['remaining']);
    header('RateLimit: remaining=' . max(0, $remaining) . ', reset=' . $retryAfter);
    $msg = $globalResult['allowed']
        ? 'Too many enquiries from your location. Please try again later.'
        : 'We are experiencing a high volume of enquiries. Please try again shortly.';
    respond(429, false, $msg);
}
// Emit observability headers for allowed requests too.
header('RateLimit-Policy: ' . RATE_LIMIT_IP_MAX . ';w=' . RATE_LIMIT_WINDOW);
header('RateLimit: remaining=' . max(0, $ipResult['remaining']) . ', reset=' . $ipResult['reset']);

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
    'Training',
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

// Secondary dimension: per-(hashed)email anti-relay cap. Guards against an
// attacker using many IPs to flood a single victim's inbox via the auto-reply.
$emailResult = $limiter->attempt('email:' . strtolower($email), RATE_LIMIT_EMAIL_MAX, RATE_LIMIT_WINDOW);
if (!$emailResult['allowed']) {
    header('Retry-After: ' . $emailResult['reset']);
    header('RateLimit-Policy: ' . RATE_LIMIT_EMAIL_MAX . ';w=' . RATE_LIMIT_WINDOW);
    header('RateLimit: remaining=0, reset=' . $emailResult['reset']);
    respond(429, false, 'We have already received your enquiry and will be in touch. Please wait before submitting again.');
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

/* ------------------ branded cross-platform email templates ---------------- */
/**
 * Escape a value for safe inclusion in HTML email bodies. Every piece of
 * user-supplied content rendered into the HTML part is passed through this to
 * prevent HTML/script injection inside the email (and downstream clients).
 */
function esc(string $v): string
{
    return htmlspecialchars($v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Build a branded, cross-platform HTML email. Uses table-based layout with
 * inline styles and bgcolor fallbacks so it renders in Outlook (Word engine),
 * Gmail, Apple Mail, Yahoo and mobile clients. The dark brand header carries
 * the logo image (with alt-text fallback) and a red accent line; the body is a
 * white card for readability. Returns a complete HTML document string.
 *
 * @param string $preheader  Short summary shown in inbox preview text.
 * @param string $heading    Card heading line (already-safe text).
 * @param string $bodyHtml   Inner HTML content (rows built by emailRow/emailCta).
 */
function renderEmailHtml(string $baseUrl, string $preheader, string $heading, string $bodyHtml): string
{
    $logo = esc($baseUrl . '/logo.jpg');
    $pre = esc($preheader);
    $h = $heading; // heading passed pre-escaped by caller
    // Brand palette (matches the site): dark navy, red accent, cyan, off-white.
    return '<!DOCTYPE html>'
        . '<html lang="en"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
        . '<title>' . $h . '</title></head>'
        . '<body style="margin:0;padding:0;background-color:#e8eef1;font-family:Arial,Helvetica,sans-serif;">'
        // Preheader (hidden preview text) — widely supported.
        . '<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">' . $pre . '</div>'
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#e8eef1;padding:24px 0;">'
        . '<tr><td align="center">'
        // Outlook fixed-width container.
        . '<!--[if mso]><table role="presentation" width="600" cellpadding="0" cellspacing="0"><tr><td><![endif]-->'
        . '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:600px;margin:0 auto;background-color:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(7,19,27,.12);">'
        // --- Brand header ---
        . '<tr><td style="background-color:#0a1821;padding:0;">'
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
        . '<tr><td height="4" style="line-height:4px;font-size:4px;background-color:#ef2638;">&nbsp;</td></tr>'
        . '<tr><td style="padding:20px 28px;">'
        . '<img src="' . $logo . '" alt="Top Focus Medicare Limited" width="168" style="display:block;border:0;max-width:168px;height:auto;" />'
        . '</td></tr></table></td></tr>'
        // --- Body card ---
        . '<tr><td style="padding:30px 28px 10px 28px;">'
        . '<h1 style="margin:0 0 18px 0;font-size:20px;line-height:26px;color:#0a1821;font-weight:bold;">' . $h . '</h1>'
        . $bodyHtml
        . '</td></tr>'
        // --- Footer ---
        . '<tr><td style="padding:18px 28px 28px 28px;border-top:1px solid #e3e9ec;">'
        . '<p style="margin:0 0 6px 0;font-size:13px;line-height:18px;color:#1f6386;font-weight:bold;">Top Focus Medicare Limited</p>'
        . '<p style="margin:0;font-size:12px;line-height:17px;color:#6b7d86;">Caring for you and your family &middot; topfocusmedicareltd.com.ng</p>'
        . '<p style="margin:6px 0 0 0;font-size:11px;line-height:16px;color:#93a3ac;">This message was generated by the website enquiry form. If you did not expect it, you may safely ignore it.</p>'
        . '</td></tr>'
        . '</table>'
        . '<!--[if mso]></td></tr></table><![endif]-->'
        . '</td></tr></table>'
        . '</body></html>';
}

/** A labelled detail row inside the email card (label + value), HTML-safe. */
function emailRow(string $label, string $value): string
{
    return '<p style="margin:0 0 12px 0;font-size:14px;line-height:20px;color:#1a2b34;">'
        . '<span style="color:#1f6386;font-weight:bold;">' . esc($label) . ': </span>'
        . esc($value) . '</p>';
}

/** A block of wrapped text (e.g. the patient message), HTML-safe. */
function emailBlock(string $label, string $value): string
{
    return '<p style="margin:0 0 14px 0;font-size:14px;line-height:20px;color:#1a2b34;">'
        . '<span style="color:#1f6386;font-weight:bold;">' . esc($label) . '</span></p>'
        . '<p style="margin:0 0 18px 0;padding:12px 14px;background-color:#f4f7f9;border-left:3px solid #2f86ad;border-radius:4px;font-size:14px;line-height:21px;color:#1a2b34;white-space:pre-wrap;">'
        . esc($value) . '</p>';
}

/** A call-to-action button (bulletproof table-based, works in Outlook). */
function emailCta(string $url, string $label, string $bg = '#ef2638'): string
{
    $u = esc($url);
    $l = esc($label);
    $b = esc($bg);
    return '<table role="presentation" cellpadding="0" cellspacing="0" style="margin:6px 0 18px 0;border-radius:6px;overflow:hidden;">'
        . '<tr><td align="center" bgcolor="' . $b . '" style="background-color:' . $b . ';border-radius:6px;">'
        . '<a href="' . $u . '" target="_blank" style="display:inline-block;padding:13px 26px;font-family:Arial,Helvetica,sans-serif;font-size:15px;font-weight:bold;color:#ffffff;text-decoration:none;border-radius:6px;">'
        . $l . '</a></td></tr></table>';
}

/**
 * Assemble a multipart/alternative MIME message (plain text + HTML) suitable
 * for PHP mail(). Returns ['headers' => string, 'body' => string]; the caller
 * merges the returned headers into its From/Reply-To headers and passes the
 * body as the message argument.
 */
function buildMultipart(string $textPart, string $htmlPart): array
{
    $boundary = 'b_' . bin2hex(random_bytes(12));
    $headers = "MIME-Version: 1.0\r\n"
        . "Content-Type: multipart/alternative; boundary=\"{$boundary}\"";
    $eol = "\r\n";
    $body = "--{$boundary}{$eol}"
        . "Content-Type: text/plain; charset=utf-8{$eol}"
        . "Content-Transfer-Encoding: 8bit{$eol}{$eol}"
        . $textPart . $eol
        . "--{$boundary}{$eol}"
        . "Content-Type: text/html; charset=utf-8{$eol}"
        . "Content-Transfer-Encoding: 8bit{$eol}{$eol}"
        . $htmlPart . $eol
        . "--{$boundary}--{$eol}";
    return ['headers' => $headers, 'body' => $body];
}

/** Encode a subject line for safe transport of non-ASCII characters. */
function encodeSubject(string $subject): string
{
    return function_exists('mb_encode_mimeheader')
        ? mb_encode_mimeheader($subject, 'UTF-8', 'Q', "\r\n")
        : $subject;
}

/* --------------------- bidirectional email dispatch ---------------------- */
$userEmailSent = false;
$adminEmailSent = 0;
$servicesList = $services ? implode(', ', $services) : 'None selected';
$methodList = $contactMethod ? implode(', ', $contactMethod) : 'None selected';

// mailFrom is header-bound, so sanitize defensively even though it is config.
$safeMailFrom = sanitizeHeaderField($mailFrom);

// --- Admin notification (all clinic inboxes) ---
$adminSubjectRaw = sprintf('[%s] New enquiry from %s (%s)', strtoupper($sentiment['label']), $name, $record['id']);
$adminSubject = sanitizeHeaderField(encodeSubject($adminSubjectRaw));

// Plain-text alternative for the admin email.
$adminText = "New enquiry received via the website.\n\n"
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
    $adminText .= "\nWhatsApp chat link (patient will also receive this):\n{$whatsappLink}\n";
}

// Branded HTML alternative for the admin email.
$sentimentBadge = match ($sentiment['label']) {
    'positive' => '<span style="display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:bold;color:#ffffff;background-color:#1f8a4c;">POSITIVE</span>',
    'negative' => '<span style="display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:bold;color:#ffffff;background-color:#c0271f;">NEGATIVE</span>',
    default => '<span style="display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:bold;color:#ffffff;background-color:#6b7d86;">NEUTRAL</span>',
};
$adminBodyHtml = '<p style="margin:0 0 16px 0;font-size:14px;line-height:20px;color:#1a2b34;">A new enquiry was received via the website. ' . $sentimentBadge . '</p>'
    . emailRow('Reference', $record['id'])
    . emailRow('Received', $record['received_at'])
    . emailRow('Sentiment', $sentiment['label'] . " (score {$sentiment['score']}; +{$sentiment['positive_hits']}/-{$sentiment['negative_hits']})")
    . emailRow('Name', $name)
    . emailRow('Email', $email)
    . emailRow('Phone', $phone !== '' ? $phone : '—')
    . emailRow('Services', $servicesList)
    . emailRow('Preferred contact', $methodList)
    . emailRow('Callback requested', $callbackRequested ? 'YES — call the patient back ASAP' : 'no')
    . emailBlock('Message', $message);
if ($whatsappLink) {
    $adminBodyHtml .= emailCta($whatsappLink, 'Open WhatsApp chat →', '#25d366')
        . '<p style="margin:0 0 4px 0;font-size:12px;line-height:17px;color:#6b7d86;">The patient will also receive this link.</p>';
}
$adminHtml = renderEmailHtml($baseUrl, 'New enquiry from ' . $name, 'New enquiry received', $adminBodyHtml);

$adminMultipart = buildMultipart($adminText, $adminHtml);
$adminHeaders = "From: " . SITE_NAME . " <{$safeMailFrom}>\r\n"
    . "Reply-To: {$name} <{$email}>\r\n"
    . $adminMultipart['headers'] . "\r\n";
if (function_exists('mail')) {
    foreach ($clinicEmails as $inbox) {
        $inbox = sanitizeHeaderField($inbox);
        if ($inbox !== '' && filter_var($inbox, FILTER_VALIDATE_EMAIL)) {
            if (@mail($inbox, $adminSubject, $adminMultipart['body'], $adminHeaders)) {
                $adminEmailSent++;
            }
        }
    }
}

// --- User confirmation (auto-reply, distinct content) ---
if ($sendUserEmail) {
    $firstName = explode(' ', $name)[0];
    $userSubjectRaw = 'We received your enquiry — ' . SITE_NAME;
    $userSubject = sanitizeHeaderField(encodeSubject($userSubjectRaw));

    // Plain-text alternative for the user email.
    $userText = "Hi {$firstName},\n\n"
        . "Thank you for reaching out to " . SITE_NAME . ". We have received your enquiry and our care team will follow up shortly.\n\n"
        . "Your reference: {$record['id']}\n"
        . "Services you asked about: {$servicesList}\n\n";
    if ($wantsWhatsapp && $whatsappLink) {
        $userText .= "You asked to be contacted on WhatsApp. Tap the link below to start the conversation with us now:\n"
            . "{$whatsappLink}\n\n";
    }
    if ($wantsCall) {
        $userText .= "You requested a phone call. A member of our team will call you back on {$phone} as soon as possible.\n\n";
    }
    if ($wantsEmail) {
        $userText .= "You'll also receive further updates by email.\n\n";
    }
    $userText .= "Your message to us:\n\"{$message}\"\n\n"
        . "If you did not submit this enquiry, please ignore this email.\n\n"
        . "Caring for you,\n"
        . SITE_NAME . "\n";

    // Branded HTML alternative for the user email.
    $userBodyHtml = '<p style="margin:0 0 16px 0;font-size:15px;line-height:22px;color:#1a2b34;">Hi ' . esc($firstName) . ',</p>'
        . '<p style="margin:0 0 16px 0;font-size:15px;line-height:22px;color:#1a2b34;">Thank you for reaching out to <strong style="color:#0a1821;">Top Focus Medicare Limited</strong>. We have received your enquiry and our care team will follow up shortly.</p>'
        . emailRow('Your reference', $record['id'])
        . emailRow('Services you asked about', $servicesList);
    if ($wantsWhatsapp && $whatsappLink) {
        $userBodyHtml .= '<p style="margin:18px 0 6px 0;font-size:14px;line-height:20px;color:#1a2b34;">You asked to be contacted on WhatsApp. Tap the button below to start the conversation with us now:</p>'
            . emailCta($whatsappLink, 'Open WhatsApp chat →', '#25d366');
    }
    if ($wantsCall) {
        $userBodyHtml .= '<p style="margin:14px 0 6px 0;font-size:14px;line-height:20px;color:#1a2b34;">You requested a phone call. A member of our team will call you back on <strong style="color:#0a1821;">' . esc($phone) . '</strong> as soon as possible.</p>';
    }
    if ($wantsEmail) {
        $userBodyHtml .= '<p style="margin:14px 0 6px 0;font-size:14px;line-height:20px;color:#1a2b34;">You&rsquo;ll also receive further updates by email.</p>';
    }
    $userBodyHtml .= emailBlock('Your message to us', $message)
        . '<p style="margin:18px 0 6px 0;font-size:13px;line-height:18px;color:#6b7d86;">If you did not submit this enquiry, please ignore this email.</p>'
        . '<p style="margin:0;font-size:14px;line-height:20px;color:#1a2b34;">Caring for you,<br /><strong style="color:#0a1821;">Top Focus Medicare Limited</strong></p>';
    $userHtml = renderEmailHtml($baseUrl, 'Your enquiry to Top Focus Medicare Limited has been received', 'We received your enquiry', $userBodyHtml);

    $userMultipart = buildMultipart($userText, $userHtml);
    $userHeaders = "From: " . SITE_NAME . " <{$safeMailFrom}>\r\n"
        . "Reply-To: " . sanitizeHeaderField($clinicEmails[0] ?? '') . "\r\n"
        . $userMultipart['headers'] . "\r\n";
    if (function_exists('mail')) {
        $userEmailSent = @mail($email, $userSubject, $userMultipart['body'], $userHeaders);
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
