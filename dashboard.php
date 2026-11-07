<?php
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/layout.php';
$user = require_login();
$devices = $pdo->query('SELECT COUNT(*) FROM devices')->fetchColumn();
$vulns = $pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'Open'")->fetchColumn();
$avg = $pdo->query('SELECT AVG(cvss_score) FROM vulnerabilities')->fetchColumn();
$alerts = $pdo->query('SELECT COUNT(*) FROM ids_alerts')->fetchColumn();
$sev = []; foreach ($pdo->query("SELECT risk_level, COUNT(*) n FROM vulnerabilities GROUP BY risk_level") as $r) $sev[$r['risk_level']] = $r['n'];
$layers = []; foreach ($pdo->query("SELECT layer, COUNT(*) n FROM vulnerabilities GROUP BY layer") as $r) $layers[$r['layer']] = $r['n'];
$top = $pdo->query('SELECT d.device_name, d.ip_address, COUNT(v.id) n, MAX(v.cvss_score) mx FROM devices d LEFT JOIN vulnerabilities v ON v.device_id = d.id GROUP BY d.id ORDER BY mx DESC, n DESC')->fetchAll();
$scans = $pdo->query('SELECT s.*, u.username FROM scans s JOIN users u ON u.id = s.user_id ORDER BY s.id DESC LIMIT 5')->fetchAll();
$ids = $pdo->query('SELECT * FROM ids_runs ORDER BY id DESC LIMIT 1')->fetch();
page_header('Dashboard Overview', 'dashboard', $user);
$colors = ['Critical'=>'var(--crit)','High'=>'var(--high)','Medium'=>'var(--med)','Low'=>'var(--low)']; $maxs = max([1] + array_values($sev)); ?>
<div class="grid">
<div class="card kpi"><div class="l">Devices scanned</div><div class="n"><?= (int)$devices ?></div></div>
<div class="card kpi"><div class="l">Open vulnerabilities</div><div class="n"><?= (int)$vulns ?></div></div>
<div class="card kpi"><div class="l">Mean CVSS score</div><div class="n"><?= $avg !== null ? number_format((float)$avg, 1) : '-' ?></div></div>
<div class="card kpi"><div class="l">Intrusion alerts</div><div class="n"><?= (int)$alerts ?></div></div></div>
<div class="two"><div class="card"><h2>Findings by severity (CVSS v3.1)</h2>
<?php foreach ($colors as $k => $c): $n = $sev[$k] ?? 0; ?><div class="bar"><span class="lb"><?= $k ?></span><div class="track"><div class="fill" style="width:<?= 100*$n/$maxs ?>%;background:<?= $c ?>"></div></div><b><?= $n ?></b></div><?php endforeach; ?>
<h2 style="margin-top:18px">Findings by layer</h2>
<?php foreach (['network','firmware','hardware'] as $l): $n = $layers[$l] ?? 0; ?><div class="bar"><span class="lb"><?= ucfirst($l) ?></span><div class="track"><div class="fill" style="width:<?= 100*$n/max(1,array_sum($layers)) ?>%;background:var(--accent2)"></div></div><b><?= $n ?></b></div><?php endforeach; ?>
</div>
<div class="card"><h2>Devices ranked by highest CVSS score</h2><table><tr><th>Device</th><th>IP</th><th>Findings</th><th>Max CVSS</th></tr>
<?php foreach ($top as $t): ?><tr><td><?= e($t['device_name']) ?></td><td class="mono"><?= e($t['ip_address']) ?></td><td><?= (int)$t['n'] ?></td>
<td><?= $t['mx'] !== null ? number_format((float)$t['mx'],1) . ' ' : '' ?></td></tr><?php endforeach; ?></table></div></div>
<div class="two"><div class="card"><h2>Recent scans</h2><table><tr><th>ID</th><th>Range</th><th>Type</th><th>Hosts</th><th>Started</th><th>By</th></tr>
<?php foreach ($scans as $s): ?><tr><td><?= (int)$s['id'] ?></td><td class="mono"><?= e($s['network_range']) ?></td><td><?= e($s['scan_type']) ?></td><td><?= (int)$s['hosts_found'] ?></td><td><?= e($s['started_at']) ?></td><td><?= e($s['username']) ?></td></tr><?php endforeach; ?></table></div>
<div class="card"><h2>Intrusion detection model</h2><?php if ($ids): ?>
<table><tr><th>Model</th><td><?= e($ids['model']) ?></td></tr><tr><th>Accuracy</th><td><?= number_format(100*$ids['accuracy'],2) ?>%</td></tr>
<tr><th>False positive rate</th><td><?= number_format(100*$ids['fpr'],2) ?>%</td></tr><tr><th>Inference time</th><td><?= e($ids['latency_ms_per_1000']) ?> ms per 1,000 flows</td></tr>
<tr><th>Dataset</th><td class="note"><?= e($ids['dataset']) ?></td></tr></table>
<?php else: ?><p class="muted">Model not yet trained.</p><?php endif; ?></div></div>
<?php page_footer();
