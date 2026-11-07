<?php
/* Session handling: secure cookie flags, inactivity timeout, role checks, CSRF tokens. */
session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => !empty($_SERVER['HTTPS'])]);
session_start();
const SESSION_TIMEOUT = 900; // 15 minutes
function require_login(?string $role = null): array {
    if (empty($_SESSION['user_id'])) { header('Location: index.php'); exit; }
    if (time() - ($_SESSION['last_seen'] ?? 0) > SESSION_TIMEOUT) {
        session_unset(); session_destroy(); header('Location: index.php?expired=1'); exit;
    }
    $_SESSION['last_seen'] = time();
    if ($role && $_SESSION['role'] !== $role) { http_response_code(403); exit('Access denied: analyst role required.'); }
    return ['id' => $_SESSION['user_id'], 'username' => $_SESSION['username'], 'role' => $_SESSION['role']];
}
function csrf_token(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function check_csrf(): void {
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(400); exit('Invalid form token.'); }
}
function e($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
