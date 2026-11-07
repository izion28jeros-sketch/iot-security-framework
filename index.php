<?php
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/auth.php';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $st = $pdo->prepare('SELECT id, username, password_hash, role FROM users WHERE username = ?');   // prepared statement: no SQL injection
    $st->execute([$username]);
    $user = $st->fetch();
    if ($user && password_verify($password, $user['password_hash'])) {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id']; $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role']; $_SESSION['last_seen'] = time();
        header('Location: dashboard.php'); exit;
    }
    usleep(500000);                       // slow down password guessing
    $error = 'Invalid username or password.';
}
?><!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Login | IoT Security Assessment</title>
<link rel="stylesheet" href="assets/style.css"></head><body style="background:#16263d">
<div class="login"><h1>&#9670; IoT Security Assessment</h1><p class="muted" style="margin-top:0">Multi-layer vulnerability assessment for smart home devices</p>
<?php if (isset($_GET['expired'])): ?><div class="err">Your session expired. Please log in again.</div><?php endif; ?>
<?php if ($error): ?><div class="err"><?= e($error) ?></div><?php endif; ?>
<form method="post" autocomplete="off"><label>Username</label><input type="text" name="username" required>
<label>Password</label><input type="password" name="password" required><button type="submit">Log in</button></form>
<p class="note">Authorised testing only. Scans are restricted to the private testbed network.</p></div></body></html>
