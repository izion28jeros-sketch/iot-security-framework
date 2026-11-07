<?php
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/layout.php';
$user = require_login();
$devs = $pdo->query('SELECT * FROM devices ORDER BY ip_address')->fetchAll();
$st = $pdo->prepare('SELECT * FROM vulnerabilities WHERE device_id = ? ORDER BY cvss_score DESC');
page_header('Assessment Report', 'report', $user); ?>
<div class="card noprint"><button onclick="window.print()">Print / Save as PDF</button> <span class="note">Generated <?= date('Y-m-d H:i') ?> by <?= e($user['username']) ?></span></div>
<?php foreach ($devs as $d): $st->execute([$d['id']]); $v = $st->fetchAll(); ?>
<div class="card"><h2><?= e($d['device_name']) ?> &mdash; <span class="mono"><?= e($d['ip_address']) ?></span></h2>
<p class="note">Category: <?= e($d['category']) ?> &middot; Open ports: <?= e($d['open_ports']) ?> &middot; Firmware: <?= e($d['firmware_version'] ?? 'not analysed') ?> &middot; Findings: <?= count($v) ?></p>
<table><tr><th>#</th><th>Finding</th><th>CVSS</th><th>Severity</th><th>CWE / ATT&amp;CK</th><th>Recommended mitigation</th></tr>
<?php foreach ($v as $i => $r): ?><tr><td><?= $i+1 ?></td><td><?= e($r['vulnerability']) ?></td><td><?= number_format((float)$r['cvss_score'],1) ?></td><td><?= sev_badge($r['risk_level']) ?></td><td class="mono"><?= e($r['cwe_id']) ?><br><?= e($r['attack_technique']) ?></td><td class="note"><?= e($r['recommendation']) ?></td></tr><?php endforeach; ?>
</table></div><?php endforeach; page_footer();
