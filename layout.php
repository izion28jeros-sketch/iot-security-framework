<?php
function page_header(string $title, string $active, array $user): void { ?>
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($title) ?> | IoT Security Assessment</title><link rel="stylesheet" href="assets/style.css"></head><body>
<aside class="side"><div class="brand"><span class="logo">&#9670;</span> IoT Security<br><small>Assessment Framework</small></div><nav>
<?php foreach (['dashboard'=>'Dashboard','scan'=>'Network Scan','devices'=>'Devices','vulnerabilities'=>'Vulnerabilities','firmware'=>'Firmware Analysis','hardware'=>'Hardware Inspection','ids'=>'Intrusion Detection','report'=>'Assessment Report'] as $k=>$v): ?>
<a href="<?= $k ?>.php" class="<?= $active===$k?'on':'' ?>"><?= $v ?></a>
<?php endforeach; ?></nav>
<div class="who"><?= e($user['username']) ?> &middot; <?= e($user['role']) ?><br><a href="logout.php">Log out</a></div></aside>
<main><header class="top"><h1><?= e($title) ?></h1><span class="tb">Testbed: isolated network</span></header>
<?php }
function page_footer(): void { echo "</main></body></html>"; }
function sev_badge(string $s): string { return '<span class="sev sev-' . strtolower($s) . '">' . e($s) . '</span>'; }
