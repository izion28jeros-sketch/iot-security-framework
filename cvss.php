<?php
/* CVSS v3.1 base score calculator (FIRST specification, section 7). */
function cvss_roundup(float $x): float {
    $i = (int) round($x * 100000);
    return ($i % 10000 === 0) ? $i / 100000.0 : (floor($i / 10000) + 1) / 10.0;
}
function cvss31_score(string $vector): float {
    $m = [];
    foreach (explode('/', $vector) as $part) {
        if (strpos($part, ':') !== false) { [$k, $v] = explode(':', $part); $m[$k] = $v; }
    }
    $AV = ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2][$m['AV']];
    $AC = ['L' => 0.77, 'H' => 0.44][$m['AC']];
    $changed = ($m['S'] === 'C');
    $PR = ['N' => 0.85, 'L' => $changed ? 0.68 : 0.62, 'H' => $changed ? 0.5 : 0.27][$m['PR']];
    $UI = ['N' => 0.85, 'R' => 0.62][$m['UI']];
    $cia = ['H' => 0.56, 'L' => 0.22, 'N' => 0.0];
    $iss = 1 - (1 - $cia[$m['C']]) * (1 - $cia[$m['I']]) * (1 - $cia[$m['A']]);
    $impact = $changed ? 7.52 * ($iss - 0.029) - 3.25 * pow($iss - 0.02, 15) : 6.42 * $iss;
    $expl = 8.22 * $AV * $AC * $PR * $UI;
    if ($impact <= 0) return 0.0;
    return $changed ? cvss_roundup(min(1.08 * ($impact + $expl), 10)) : cvss_roundup(min($impact + $expl, 10));
}
function cvss_severity(float $s): string {
    if ($s == 0) return 'None';
    if ($s < 4.0) return 'Low';
    if ($s < 7.0) return 'Medium';
    if ($s < 9.0) return 'High';
    return 'Critical';
}
