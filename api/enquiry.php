<?php
/**
 * Enquiry endpoint for Top Focus Medicare Limited.
 * Accepts a JSON POST from the website contact form, validates it,
 * stores it to a protected data file, optionally notifies the clinic by email,
 * and returns a JSON response.
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

header('Access-Control-Allow-Origin: ' . ($_SERVER['HTTP_ORIGIN'] ?? '*'));
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Accept');
header('Vary: Origin');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'message' => 'Method not allowed.']);
    exit;
}

function respond(int $code, bool $ok, string $message, array $extra = []): void
{
    http_response_code($code);
    echo json_encode(array_merge(['ok' => $ok, 'message' => $message], $extra));
    exit;
}

$raw = file_get_contents('php://input');
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

$name = trim((string)($data['name'] ?? ''));
$email = trim((string)($data['email'] ?? ''));
$phone = trim((string)($data['phone'] ?? ''));
$message = trim((string)($data['message'] ?? ''));

$services = $data['services'] ?? [];
$services = is_array($services) ? $services : [$services];
$services = array_values(array_filter(array_map('strval', $services), fn($v) => $v !== ''));

$contactMethod = $data['contact_method'] ?? [];
$contactMethod = is_array($contactMethod) ? $contactMethod : [$contactMethod];
$contactMethod = array_values(array_filter(array_map('strval', $contactMethod), fn($v) => $v !== ''));

$errors = [];
if ($name === '' || mb_strlen($name) > 120) {
    $errors[] = 'a valid name';
}
if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'a valid email address';
}
if ($message === '' || mb_strlen($message) > 5000) {
    $errors[] = 'a message';
}

$allowedServices = [
    'General Healthcare', 'Maternity Care', 'Infertility Care',
    'Obstetrics', 'Surgical Management', 'Diagnostics & Laboratory',
];
$services = array_values(array_intersect($services, $allowedServices));

$allowedMethods = ['WhatsApp', 'Phone call', 'Email'];
$contactMethod = array_values(array_intersect($contactMethod, $allowedMethods));

// WhatsApp / Phone call require a reachable phone number.
if (in_array('WhatsApp', $contactMethod, true) || in_array('Phone call', $contactMethod, true)) {
    if ($phone === '' || strlen(preg_replace('/[^0-9+]/', '', $phone)) < 7) {
        $errors[] = 'a valid phone number for WhatsApp/Phone call';
    }
}

if ($errors) {
    respond(422, false, 'Please provide ' . implode(', ', $errors) . '.');
}

$record = [
    'id' => bin2hex(random_bytes(8)),
    'received_at' => date('c'),
    'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
    'name' => $name,
    'email' => $email,
    'phone' => $phone,
    'services' => $services,
    'contact_method' => $contactMethod,
    'message' => $message,
];

// Persist to a protected data directory (one level above the web root).
$dataDir = __DIR__ . '/../private';
if (!is_dir($dataDir)) {
    @mkdir($dataDir, 0700, true);
}
$logFile = $dataDir . '/enquiries.jsonl';
$line = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
@file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);

// Optional email notification to the clinic.
$clinicEmail = getenv('CLINIC_EMAIL') ?: 'info@topfocusmedicareltd.com';
$siteName = 'Top Focus Medicare Limited';
$subject = 'New website enquiry from ' . $name;
$body = "New enquiry received via the website.\n\n"
    . "Name: {$name}\n"
    . "Email: {$email}\n"
    . "Phone: {$phone}\n"
    . "Services: " . ($services ? implode(', ', $services) : 'None selected') . "\n"
    . "Preferred contact: " . ($contactMethod ? implode(', ', $contactMethod) : 'None selected') . "\n"
    . "Message:\n{$message}\n\n"
    . "Received: {$record['received_at']}\n"
    . "Reference: {$record['id']}\n";

$headers = "From: {$siteName} <no-reply@topfocusmedicareltd.com>\r\n"
    . "Reply-To: {$name} <{$email}>\r\n"
    . "Content-Type: text/plain; charset=utf-8\r\n";

if (function_exists('mail')) {
    @mail($clinicEmail, $subject, $body, $headers);
}

respond(200, true, 'Thank you. Your enquiry has been received. We will reach out shortly.', ['reference' => $record['id']]);
