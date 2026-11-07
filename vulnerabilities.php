<?php
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/layout.php';
$user = require_login();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $user['role'] === 'analyst') {
    check_csrf();
    $pdo->prepare("UPDATE vulnerabilities SET status = CASE status WHEN 'Open' THEN 'Fixed' ELSE 'Open' END WHERE id = ?")->execute([(int)$_POST['id']]);
}
$layer = $_GET['layer'] ?? '';
$sql = 'SELECT v.*, d.device_name, d.ip_address FROM vulnerabilities v JOIN devices d ON d.id = v.device_id';
$params = [];
if (in_array($layer, ['network','firmware','hardware'], true)) { $sql .= ' WHERE v.layer = ?'; $params[] = $layer; }
$st = $pdo->prepare($sql . ' ORDER BY v.cvss_score DESC, d.ip_address'); $st->execute($params); $rows = $st->fetchAll();
page_header('Vulnerability Findings', 'vulnerabilities', $user); ?>
<div class="card noprint"><form method="get" class="inline"><div><label>Filter by layer</label><select name="layer"><option value="">All layers</option>
<?php foreach (['network','firmware','hardware'] as $l): ?><option value="<?= $l ?>" <?= $layer===$l?'selected':'' ?>><?= ucfirst($l) ?></option><?php endforeach; ?></select></div><button>Apply</button></form></div>
<div class="card"><table><tr><th>Device</th><th>Vulnerability</th><th>Layer</th><th>CVSS</th><th>Severity</th><th>CWE</th><th>ATT&amp;CK</th><th>Recommendation</th><th>Status</th></tr>
<?php foreach ($rows as $r): ?><tr><td><?= e($r['device_name']) ?><br><span class="mono muted"><?= e($r['ip_address']) ?></span></td>
<td><?= e($r['vulnerability']) ?><br><span class="note"><?= e($r['evidence']) ?></span></td><td><?= e(ucfirst($r['layer'])) ?></td>
<td><b><?= number_format((float)$r['cvss_score'],1) ?></b></td><td><?= sev_badge($r['risk_level']) ?></td><td class="mono"><?= e($r['cwe_id']) ?></td><td class="mono"><?= e($r['attack_technique']) ?></td>
<td class="note"><?= e($r['recommendation']) ?></td><td><?= e($r['status']) ?>
<?php if ($user['role']==='analyst'): ?><form method="post"><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int)$r['id'] ?>"><button style="padding:3px 8px;font-size:11px;margin-top:4px"><?= $r['status']==='Open'?'Mark fixed':'Reopen' ?></button></form><?php endif; ?></td></tr><?php endforeach; ?>
</table></div><?php page_footer();
