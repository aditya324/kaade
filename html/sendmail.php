<?php
// send_mail.php

declare(strict_types=1);

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as MailException;
use Dotenv\Dotenv;

// 1) Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Invalid access');
}

// 2) Autoload dependencies
require __DIR__ . '/vendor/autoload.php';

// 3) Locate & load .env (search current and parent directory)
$envLoaded = false;
foreach ([__DIR__, dirname(__DIR__)] as $dir) {
    if (file_exists($dir . '/.env') && is_readable($dir . '/.env')) {
        Dotenv::createImmutable($dir)->load();
        $envLoaded = true;
        break;
    }
}
if (! $envLoaded) {
    http_response_code(500);
    exit('Configuration error: .env file not found');
}

// 4) Sanitize & validate inputs
$name    = trim(filter_input(INPUT_POST, 'name',    FILTER_SANITIZE_STRING) ?: '');
$email   = trim(filter_input(INPUT_POST, 'email',   FILTER_SANITIZE_EMAIL)  ?: '');
$subject = trim(filter_input(INPUT_POST, 'subject', FILTER_SANITIZE_STRING) ?: '');
$message = trim(filter_input(INPUT_POST, 'message', FILTER_UNSAFE_RAW)       ?: '');

if ($name === '' || $email === '' || $subject === '' || $message === '') {
    echo '<script>alert("All fields are required.");history.back();</script>';
    exit;
}
if (! filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo '<script>alert("Please enter a valid email address.");history.back();</script>';
    exit;
}

// 5) Verify reCAPTCHA
$token  = $_POST['g-recaptcha-response'] ?? '';
$secret = getenv('RECAPTCHA_SECRET') ?: '';

if ($token === '') {
    echo '<script>alert("Please complete the reCAPTCHA.");history.back();</script>';
    exit;
}
if ($secret === '') {
    http_response_code(500);
    exit('Configuration error: RECAPTCHA_SECRET not set');
}

$ch = curl_init('https://www.google.com/recaptcha/api/siteverify');
curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POSTFIELDS     => http_build_query([
        'secret'   => $secret,
        'response' => $token,
        'remoteip' => $_SERVER['REMOTE_ADDR'],
    ]),
]);
$response = curl_exec($ch);
if ($response === false) {
    $err = curl_error($ch);
    curl_close($ch);
    http_response_code(502);
    exit("reCAPTCHA verification error: {$err}");
}
curl_close($ch);

$captcha = json_decode($response, true);
if (empty($captcha['success'])) {
    $codes = implode(', ', $captcha['error-codes'] ?? ['unknown_error']);
    echo "<script>alert('reCAPTCHA failed: {$codes}');history.back();</script>";
    exit;
}

// 6) Database connection (PDO)
try {
    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=utf8mb4',
        getenv('DB_HOST') ?: '',
        getenv('DB_NAME') ?: ''
    );
    $pdo = new PDO(
        $dsn,
        getenv('DB_USER') ?: '',
        getenv('DB_PASS') ?: '',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    error_log('DB Connection Error: ' . $e->getMessage());
    echo '<script>alert("Server error. Please try again later.");history.back();</script>';
    exit;
}

try {
    // 7) Configure PHPMailer
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host        = getenv('SMTP_HOST') ?: '';
    $mail->SMTPAuth    = filter_var(getenv('SMTP_AUTH') ?? 'false', FILTER_VALIDATE_BOOLEAN);
    $mail->Username    = getenv('SMTP_USER') ?: '';
    $mail->Password    = getenv('SMTP_PASS') ?: '';
    $mail->SMTPSecure  = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port        = (int)(getenv('SMTP_PORT') ?: 587);
    $mail->SMTPAutoTLS = false;
    $mail->SMTPOptions = [
        'ssl' => [
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
        ],
    ];

    // 8) Build the message
    $mail->setFrom(getenv('MAIL_FROM_ADDRESS') ?: $mail->Username, getenv('MAIL_FROM_NAME') ?: '');
    $mail->addAddress(getenv('MAIL_TO_ADDRESS') ?: $mail->Username);
    $mail->addReplyTo($email, $name);

    $mail->Subject = $subject;
    $mail->isHTML(true);
    $mail->CharSet = 'UTF-8';
    $mail->Body    = nl2br(htmlspecialchars($message, ENT_QUOTES, 'UTF-8'));
    $mail->AltBody = strip_tags($message);

    // 9) Send it
    $mail->send();

    // 10) Save to DB
    $stmt = $pdo->prepare('
        INSERT INTO sent_mails (name, email, subject, message, sent_at)
        VALUES (:name, :email, :subject, :message, NOW())
    ');
    $stmt->execute([
        ':name'    => $name,
        ':email'   => $email,
        ':subject' => $subject,
        ':message' => $message,
    ]);

    // 11) Success feedback
    echo '<p class="success">Thank you! Your message has been sent.</p>';

} catch (MailException $e) {
    error_log('PHPMailer Error: ' . $e->getMessage());
    $msg = addslashes($e->getMessage());
    echo "<script>alert(\"Error sending email: {$msg}\");history.back();</script>";
    exit;
} catch (Exception $e) {
    error_log('General Error: ' . $e->getMessage());
    echo '<script>alert("An unexpected error occurred.");history.back();</script>';
    exit;
}
