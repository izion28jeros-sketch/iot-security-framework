<?php
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/layout.php';
require __DIR__ . '/includes/store.php';
$user = require_login('analyst');
$devices = $pdo->query('SELECT id, device_name, ip_address FROM devices ORDER BY ip_address')->fetchAll();
$report = null; $error = ''; $dev_id = (int)($_POST['device_id'] ?? 0);
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $f = $_FILES['image'] ?? null;
    if (!$dev_id || !$f || $f['error'] !== UPLOAD_ERR_OK) { $error = 'Choose a device and a firmware image.'; }
    elseif ($f['size'] > 200 * 1024 * 1024) { $error = 'Image larger than 200 MB.'; }
    else {
        $dest = __DIR__ . '/uploads/' . bin2hex(random_bytes(8)) . '.img';   // random name: never trust the uploaded file name
        move_uploaded_file($f['tmp_name'], $dest);
        $sha = hash_file('sha256', $dest);
        $out = shell_exec('python3 ' . escapeshellarg(__DIR__ . '/ml/firmware_analyzer.py') . ' ' . escapeshellarg($dest) . ' 2>&1');
        $report = json_decode((string)$out, true);
        unlink($dest);
        if (!$report || isset($report['error'])) { $error = 'Analysis failed: ' . ($report['error'] ?? 'unreadable output'); $report = null; }
        else {
            $pdo->prepare('INSERT INTO scans (user_id, network_range, scan_type, started_at, ended_at, hosts_found) VALUES (?,?,?,?,?,1)')
                ->execute([$user['id'], 'firmware', 'Firmware', date('Y-m-d H:i:s'), date('Y-m-d H:i:s')]);
            $scan_id = (int)$pdo->lastInsertId();
            foreach ($report['findings'] as $fd) store_finding($pdo, $dev_id, $scan_id, $fd['rule'], $fd['evidence']);
            if ($report['fw_version']) $pdo->prepare('UPDATE devices SET firmware_version = ? WHERE id = ?')->execute([$report['fw_version'], $dev_id]);
            $report['name'] = $f['name']; $report['sha'] = $sha; $report['size'] = $f['size'];
        }
    }
}
page_header('Firmware Analysis', 'firmware', $user); ?>
<?php if ($error): ?><div class="err"><?= e($error) ?></div><?php endif; ?>
<div class="card"><h2>Analyse a firmware image (Module 2)</h2>
<form method="post" enctype="multipart/form-data" class="inline"><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
<div><label>Device</label><select name="device_id"><?php foreach ($devices as $d): ?><option value="<?= (int)$d['id'] ?>" <?= $dev_id===(int)$d['id']?'selected':'' ?>><?= e($d['device_name'] . ' (' . $d['ip_address'] . ')') ?></option><?php endforeach; ?></select></div>
<div><label>Firmware image (.bin, .img, .tar.gz)</label><input type="file" name="image" required></div><button type="submit">Extract and Analyse</button></form>
<p class="note">Extraction: tar root file systems directly; other images with binwalk. Checks: hardcoded credentials, plaintext secrets, embedded private keys, telnetd in start-up scripts, unsigned update routine, outdated libraries, image encryption.</p></div>
<?php if ($report): ?><div class="ok">Firmware analysed: <?= count($report['findings']) ?> findings stored for the selected device.</div>
<div class="two"><div class="card"><h2>Firmware information</h2><table>
<tr><th>File name</th><td><?= e($report['name']) ?></td></tr><tr><th>Size</th><td><?= number_format($report['size']) ?> bytes</td></tr>
<tr><th>SHA-256</th><td class="mono"><?= e(substr($report['sha'],0,32)) ?>&hellip;</td></tr><tr><th>Extraction</th><td><?= e($report['method']) ?></td></tr>
<tr><th>Files extracted</th><td><?= (int)$report['files'] ?></td></tr><tr><th>Firmware version</th><td><?= e($report['fw_version'] ?? 'not found') ?></td></tr></table></div>
<div class="card"><h2>Security issues found</h2><table><tr><th>Issue</th><th>CVSS</th><th>Severity</th><th>Evidence</th></tr>
<?php foreach ($report['findings'] as $fd): $s = cvss31_score(RULES[$fd['rule']]['vector']); ?><tr><td><?= e(RULES[$fd['rule']]['title']) ?></td><td><?= number_format($s,1) ?></td><td><?= sev_badge(cvss_severity($s)) ?></td><td class="note mono"><?= e($fd['evidence']) ?></td></tr><?php endforeach; ?>
</table></div></div><?php endif; page_footer();
