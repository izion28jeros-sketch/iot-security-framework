<?php
/* One-time setup: creates the tables (SQLite demo) and the first analyst account.
 * Usage: php setup.php <analyst_username> <password> */
require __DIR__ . '/config/database.php';
if (PHP_SAPI !== 'cli') { http_response_code(403); exit('Run from the command line.'); }
if ($DB_DRIVER === 'sqlite') {
    $sql = file_get_contents(__DIR__ . '/database/schema_mysql.sql');
    $sql = preg_replace(['/CREATE DATABASE.*?;\s*/s', '/USE .*?;\s*/', '/INT AUTO_INCREMENT PRIMARY KEY/', '/ENUM\([^)]*\)/', '/,\s*UNIQUE KEY \w+ \(([^)]*)\)/'],
                        ['', '', 'INTEGER PRIMARY KEY AUTOINCREMENT', 'TEXT', ', UNIQUE ($1)'], $sql);
    $pdo->exec($sql);
}
[$u, $p] = [$argv[1] ?? 'analyst', $argv[2] ?? null];
if (!$p || strlen($p) < 10) exit("Give a password of at least 10 characters.\n");
$st = $pdo->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)');
$st->execute([$u, password_hash($p, PASSWORD_BCRYPT), 'analyst']);
echo "Database ready. Analyst account '$u' created.\n";
