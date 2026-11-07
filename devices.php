<?php
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/layout.php';
$user = require_login();
$rows = $pdo->query('SELECT d.*, (SELECT COUNT(*) FROM vulnerabilities v WHERE v.device_id = d.id) n FROM devices d ORDER BY d.ip_address')->fetchAll();
page_header('Detected Smart Home Devices', 'devices', $user); ?>
<div class="card"><table><tr><th>ID</th><th>IP address</th><th>Device name</th><th>Category</th><th>Open ports</th><th>Firmware</th><th>Findings</th><th>Status</th><th>Date detected</th></tr>
<?php foreach ($rows as $r): ?><tr><td><?= (int)$r['id'] ?></td><td class="mono"><?= e($r['ip_address']) ?></td><td><?= e($r['device_name']) ?></td><td><?= e($r['category']) ?></td>
<td class="mono"><?= e($r['open_ports']) ?></td><td><?= e($r['firmware_version'] ?? '-') ?></td><td><?= (int)$r['n'] ?></td><td><?= e($r['status']) ?></td><td><?= e($r['scan_date']) ?></td></tr><?php endforeach; ?>
</table></div><?php page_footer();
