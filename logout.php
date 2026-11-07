<?php
require __DIR__ . '/includes/auth.php';
session_unset(); session_destroy();
header('Location: index.php');
