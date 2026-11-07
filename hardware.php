<?php
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/layout.php';
require __DIR__ . '/includes/store.php';
$user = require_login('analyst');
$devices = $pdo->query('SELECT id, device_name, ip_address FROM devices ORDER BY ip_address')->fetchAll();
$msg = '';
$hw = array_filter(RULES, fn($r) => $r['layer'] === 'hardware');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $dev = (int)$_POST['device_id']; $notes = trim($_POST['notes'] ?? ''); $n = 0;
    foreach ((array)($_POST['issues'] ?? []) as $k) if (isset($hw[$k])) { store_finding($pdo, $dev, null, $k, 'Manual bench inspection. ' . $notes); $n++; }
    $msg = "$n hardware findings recorded.";
}
$recorded = $pdo->query("SELECT v.*, d.device_name FROM vulnerabilities v JOIN devices d ON d.id = v.device_id WHERE v.layer = 'hardware' ORDER BY v.cvss_score DESC")->fetchAll();
page_header('Hardware Inspection', 'hardware', $user); ?>
<?php if ($msg): ?><div class="ok"><?= e($msg) ?></div><?php endif; ?>
<div class="card"><h2>Record bench inspection results (Module 3)</h2>
<p class="note">Open the enclosure, locate test pads with the JTAGulator / logic analyser, connect a USB-UART adapter (115200 baud) and record what was observed. Only tick what was actually confirmed on the bench.</p>
<form method="post"><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
<label>Device</label><select name="device_id"><?php foreach ($devices as $d): ?><option value="<?= (int)$d['id'] ?>"><?= e($d['device_name'] . ' (' . $d['ip_address'] . ')') ?></option><?php endforeach; ?></select>
<div style="margin:12px 0"><?php foreach ($hw as $k => $r): $s = cvss31_score($r['vector']); ?>
<label class="chk"><input type="checkbox" name="issues[]" value="<?= $k ?>"><span><?= e($r['title']) ?> &nbsp;<?= sev_badge(cvss_severity($s)) ?> <span class="mono"><?= number_format($s,1) ?> &middot; <?= e($r['cwe']) ?></span></span></label><?php endforeach; ?></div>
<label>Inspection notes (pins, baud rate, access level)</label><textarea name="notes" rows="3" style="width:100%"></textarea><br><br><button>Save inspection</button></form></div>
<div class="card"><h2>Recorded hardware findings</h2><?php if (!$recorded): ?><p class="muted">No hardware inspection has been recorded yet.</p><?php else: ?>
<table><tr><th>Device</th><th>Finding</th><th>CVSS</th><th>Notes</th></tr><?php foreach ($recorded as $r): ?><tr><td><?= e($r['device_name']) ?></td><td><?= e($r['vulnerability']) ?></td><td><?= number_format((float)$r['cvss_score'],1) ?></td><td class="note"><?= e($r['evidence']) ?></td></tr><?php endforeach; ?></table><?php endif; ?></div>
<?php page_footer();
