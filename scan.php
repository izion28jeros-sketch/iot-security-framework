<?php
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/layout.php';
require __DIR__ . '/includes/scanner.php';
require __DIR__ . '/includes/store.php';
$user = require_login('analyst');
$message = ''; $error = ''; $results = [];
$range = $_POST['range'] ?? '127.0.10.0/24';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $hosts = validate_range($range);
    if ($hosts === null) {
        $error = 'Rejected: the range must be a private testbed range between /24 and /32 (10/8, 172.16/12, 192.168/16 or 127/8).';
    } else {
        $start = date('Y-m-d H:i:s'); $t0 = microtime(true);
        $pdo->prepare('INSERT INTO scans (user_id, network_range, scan_type, started_at) VALUES (?,?,?,?)')->execute([$user['id'], $range, 'Network', $start]);
        $scan_id = (int)$pdo->lastInsertId();
        $results = run_network_scan($hosts);
        $nf = 0;
        foreach ($results as $d) {
            $st = $pdo->prepare('SELECT id FROM devices WHERE ip_address = ?'); $st->execute([$d['ip']]);
            $dev = $st->fetchColumn();
            if (!$dev) {
                $pdo->prepare('INSERT INTO devices (ip_address, device_name, category, open_ports, status, scan_date) VALUES (?,?,?,?,?,?)')
                    ->execute([$d['ip'], $d['name'], guess_category($d['name']), implode(', ', $d['ports']), 'Active', $start]);
                $dev = $pdo->lastInsertId();
            } else {
                $pdo->prepare('UPDATE devices SET open_ports = ?, status = ?, scan_date = ? WHERE id = ?')->execute([implode(', ', $d['ports']), 'Active', $start, $dev]);
            }
            foreach ($d['findings'] as $rule => $ev) { store_finding($pdo, (int)$dev, $scan_id, $rule, $ev); $nf++; }
        }
        $secs = round(microtime(true) - $t0, 2);
        $pdo->prepare('UPDATE scans SET ended_at = ?, hosts_found = ? WHERE id = ?')->execute([date('Y-m-d H:i:s'), count($results), $scan_id]);
        $message = 'Scan #' . $scan_id . ' completed in ' . $secs . ' s: ' . count($hosts) . ' addresses probed, ' . count($results) . ' devices found, ' . $nf . ' network findings recorded.';
    }
}
page_header('Network Scan', 'scan', $user); ?>
<?php if ($message): ?><div class="ok"><?= e($message) ?></div><?php endif; ?>
<?php if ($error): ?><div class="err"><?= e($error) ?></div><?php endif; ?>
<div class="card"><h2>Start network analysis (Module 1)</h2>
<form method="post" class="inline"><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
<div><label>Testbed network range (CIDR)</label><input type="text" name="range" value="<?= e($range) ?>"></div>
<button type="submit" name="scan">Start Security Scan</button></form>
<p class="note">Engine: <?= trim((string)shell_exec('command -v nmap')) ? 'Nmap (-sn, -sV)' : 'built-in TCP connect scan with banner grabbing (Nmap not installed)' ?>.
Ports probed: <?= implode(', ', IOT_PORTS) ?>.</p></div>
<?php if ($results): ?><div class="card"><h2>Scan results</h2><table><tr><th>IP address</th><th>Device</th><th>Open ports</th><th>Findings</th></tr>
<?php foreach ($results as $d): ?><tr><td class="mono"><?= e($d['ip']) ?></td><td><?= e($d['name']) ?></td><td class="mono"><?= e(implode(', ', $d['ports'])) ?></td>
<td><?php foreach ($d['findings'] as $k => $ev) { $s = cvss31_score(RULES[$k]['vector']); echo sev_badge(cvss_severity($s)) . ' ' . e(RULES[$k]['title']) . '<br>'; } ?></td></tr><?php endforeach; ?>
</table></div><?php endif; page_footer();
