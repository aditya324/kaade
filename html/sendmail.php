<?php
// send_mail.php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;
use Dotenv\Dotenv;

// 1) Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    exit('Invalid access');
}

// 2) Load .env
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/vendor/phpmailer/phpmailer/src/PHPMailer.php';
require __DIR__ . '/vendor/phpmailer/phpmailer/src/SMTP.php';
require __DIR__ . '/vendor/phpmailer/phpmailer/src/Exception.php';
require __DIR__ . '/vendor/vlucas/phpdotenv/src/Dotenv.php';
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();




// 3) Sanitize & validate inputs
$name    = trim(filter_input(INPUT_POST, 'name',    FILTER_SANITIZE_STRING)) ?? '';
$email   = trim(filter_input(INPUT_POST, 'email',   FILTER_SANITIZE_EMAIL))  ?? '';
$subject = trim(filter_input(INPUT_POST, 'subject', FILTER_SANITIZE_STRING)) ?? '';
$message = trim(filter_input(INPUT_POST, 'message', FILTER_UNSAFE_RAW))       ?? '';

// Basic validation
if (!$name || !$email || !$subject || !$message) {
    echo '<script>alert("All fields are required.");window.history.back();</script>';
    exit;
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo '<script>alert("Please enter a valid email address.");window.history.back();</script>';
    exit;
}

// 4) Google reCAPTCHA verification
$recaptchaResponse = $_POST['g-recaptcha-response'] ?? '';
if (!$recaptchaResponse) {
    echo '<script>alert("Please complete the reCAPTCHA.");window.history.back();</script>';
    exit;
}
$verifyUrl = 'https://www.google.com/recaptcha/api/siteverify'
           . '?secret='   . urlencode($_ENV['RECAPTCHA_SECRET'])
           . '&response=' . urlencode($recaptchaResponse);
$verify    = file_get_contents($verifyUrl);
$captcha   = json_decode($verify);
if (empty($captcha->success)) {
    echo '<script>alert("reCAPTCHA verification failed.");window.history.back();</script>';
    exit;
}

// 5) Database connection (PDO)
try {
    $dsn = sprintf(
      'mysql:host=%s;dbname=%s;charset=utf8mb4',
      $_ENV['DB_HOST'], 
      $_ENV['DB_NAME']
    );
    $pdo = new PDO($dsn, $_ENV['DB_USER'], $_ENV['DB_PASS'], [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);
} catch (PDOException $e) {
    error_log('DB Connection Error: ' . $e->getMessage());
    echo '<script>alert("Server error. Please try again later.");window.history.back();</script>';
    exit;
}

try {
    // 6) Prepare PHPMailer
    $mail = new PHPMailer(true);
    $mail->SMTPDebug    = SMTP::DEBUG_OFF;  // Or DEBUG_SERVER for dev
    $mail->Debugoutput  = function($str, $level) {
        error_log("SMTP DEBUG level $level; message: $str");
    };
    $mail->isSMTP();
    $mail->Host         = $_ENV['SMTP_HOST'];
    $mail->SMTPAuth     = false;
    $mail->Username     = $_ENV['SMTP_USER'];
    $mail->Password     = $_ENV['SMTP_PASS'];
    $mail->SMTPSecure   = PHPMailer::ENCRYPTION_STARTTLS; // 'tls'
    $mail->Port         = (int)$_ENV['SMTP_PORT'];
    $mail->SMTPAutoTLS  = false;
    $mail->SMTPOptions  = [
        'ssl' => [
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
        ],
    ];

    // 7) Set email headers & body
    $mail->setFrom($_ENV['SMTP_USER'], $_ENV['MAIL_FROM_NAME']);
    $mail->addAddress($_ENV['SMTP_USER'], $_ENV['MAIL_FROM_NAME']);
    $mail->addReplyTo($email, $name);

    $mail->Subject = 'Test';
    $mail->isHTML(true);
    $mail->CharSet = 'UTF-8';
    $mail->Body = 'Test message';
    $mail->AltBody = strip_tags($message);

    // 8) Send mail
    $mail->send();

    // 9) Save to database
    $stmt = $pdo->prepare(
      'INSERT INTO sent_mails (name, email, subject, message)
       VALUES (:name, :email, :subject, :message)'
    );
    $stmt->execute([
      ':name'    => $name,
      ':email'   => $email,
      ':subject' => $subject,
      ':message' => $message
    ]);

    // 10) Success feedback
    echo '<p class="success">Thank you! Your message has been sent.</p>';

} catch (Exception $e) {
    error_log('Mailer Error: ' . $e->getMessage());
    $msg = addslashes($e->getMessage());
    echo "<script>
            alert(\"Error sending email: {$msg}\");
            window.history.back();
          </script>";
    exit;
}
