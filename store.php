<?php
require_once __DIR__ . '/checks.php';
require_once __DIR__ . '/cvss.php';
/* Saves one finding with its CVSS score, CWE, ATT&CK technique and recommendation. */
function store_finding(PDO $pdo, int $device_id, ?int $scan_id, string $rule_key, string $evidence): void {
    $r = RULES[$rule_key];
    $score = cvss31_score($r['vector']);
    $st = $pdo->prepare('SELECT id FROM vulnerabilities WHERE device_id = ? AND rule_key = ?');
    $st->execute([$device_id, $rule_key]);
    if ($id = $st->fetchColumn()) {
        $pdo->prepare('UPDATE vulnerabilities SET evidence = ?, scan_id = ? WHERE id = ?')->execute([$evidence, $scan_id, $id]);
        return;
    }
    $pdo->prepare('INSERT INTO vulnerabilities (device_id, scan_id, rule_key, vulnerability, layer, evidence, cwe_id, cvss_vector, cvss_score, risk_level, attack_technique, recommendation)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
        ->execute([$device_id, $scan_id, $rule_key, $r['title'], $r['layer'], $evidence, $r['cwe'], $r['vector'], $score, cvss_severity($score), $r['attack'], $r['fix']]);
}
function guess_category(string $name): string {
    foreach (['camera'=>'Smart camera','cam'=>'Smart camera','plug'=>'Smart plug','thermostat'=>'Thermostat','voice'=>'Voice assistant','hub'=>'Voice assistant','bulb'=>'Smart bulb'] as $k=>$v)
        if (stripos($name, $k) !== false) return $v;
    return 'Other';
}
