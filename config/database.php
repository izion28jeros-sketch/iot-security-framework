<?php
/* Database connection (PDO).
 * Production: MySQL (XAMPP/LAMP). Set DB_DRIVER=mysql and the credentials below.
 * Portable demo: SQLite file in data/iot_security.sqlite (default). */
date_default_timezone_set('Africa/Lagos');
$DB_DRIVER = getenv('DB_DRIVER') ?: 'sqlite';
try {
    if ($DB_DRIVER === 'mysql') {
        $pdo = new PDO('mysql:host=127.0.0.1;dbname=iot_security;charset=utf8mb4', 'iotsec_user', getenv('DB_PASS') ?: '');
    } else {
        $pdo = new PDO('sqlite:' . __DIR__ . '/../data/iot_security.sqlite');
        $pdo->exec('PRAGMA foreign_keys = ON');
    }
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    http_response_code(500);
    exit('Database connection failed.');
}
