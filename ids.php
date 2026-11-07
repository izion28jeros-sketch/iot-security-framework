<?php
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/layout.php';
$user = require_login();
$run = $pdo->query('SELECT * FROM ids_runs ORDER BY id DESC LIMIT 1')->fetch();
$alerts = $pdo->query('SELECT * FROM ids_alerts ORDER BY alert_time DESC LIMIT 12')->fetchAll();
$counts = []; foreach ($pdo->query('SELECT attack_type, COUNT(*) n FROM ids_alerts GROUP BY attack_type') as $r) $counts[$r['attack_type']] = $r['n'];
$pc = $run ? json_decode($run['per_class_json'], true) : null;
page_header('Intrusion Detection', 'ids', $user); ?>
<?php if (!$run): ?><div class="card"><p class="muted">No model has been trained. Run: python3 ml/ids_model.py data/flows.csv data/iot_security.sqlite</p></div><?php else: ?>
<div class="grid"><div class="card kpi"><div class="l">Multi-class accuracy</div><div class="n"><?= number_format(100*$run['accuracy'],2) ?>%</div></div>
<div class="card kpi"><div class="l">Attack vs normal accuracy</div><div class="n"><?= number_format(100*$pc['_binary_accuracy'],2) ?>%</div></div>
<div class="card kpi"><div class="l">False positive rate</div><div class="n"><?= number_format(100*$run['fpr'],2) ?>%</div></div>
<div class="card kpi"><div class="l">Inference time / 1,000 flows</div><div class="n"><?= e($run['latency_ms_per_1000']) ?> ms</div></div></div>
<div class="two"><div class="card"><h2>Per-class performance (test split, <?= (int)$run['n_test'] ?> flows)</h2>
<table><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1-score</th><th>Support</th></tr>
<?php foreach (['normal','dos','mitm'] as $c): ?><tr><td><?= strtoupper($c) ?></td><td><?= number_format(100*$pc[$c]['precision'],2) ?>%</td><td><?= number_format(100*$pc[$c]['recall'],2) ?>%</td><td><?= number_format(100*$pc[$c]['f1-score'],2) ?>%</td><td><?= (int)$pc[$c]['support'] ?></td></tr><?php endforeach; ?></table>
<h2 style="margin-top:16px">Confusion matrix (rows = actual, columns = predicted)</h2>
<table><tr><th></th><th>NORMAL</th><th>DOS</th><th>MITM</th></tr><?php foreach (['NORMAL','DOS','MITM'] as $i => $c): ?><tr><th><?= $c ?></th><?php foreach ($pc['_confusion'][$i] as $v): ?><td><?= (int)$v ?></td><?php endforeach; ?></tr><?php endforeach; ?></table>
<p class="note">Model: <?= e($run['model']) ?>. Data: <?= e($run['dataset']) ?>. Trained <?= e($run['run_at']) ?>.</p></div>
<div class="card"><h2>Recent alerts (replay of held-out test flows)</h2><p class="note">DoS: <?= (int)($counts['DOS'] ?? 0) ?> &middot; MITM: <?= (int)($counts['MITM'] ?? 0) ?></p>
<table><tr><th>Time</th><th>Type</th><th>Source</th><th>Target</th><th>Confidence</th></tr><?php foreach ($alerts as $a): ?><tr><td><?= e(substr($a['alert_time'],11)) ?></td>
<td><?= sev_badge($a['attack_type']==='DOS'?'High':'Critical') ?> <?= e($a['attack_type']) ?></td><td class="mono"><?= e($a['source_ip']) ?></td><td class="mono"><?= e($a['dest_ip']) ?></td><td><?= number_format(100*$a['confidence'],1) ?>%</td></tr><?php endforeach; ?></table></div></div>
<?php endif; page_footer();
