<?php
/* Network analysis module.
 * Uses Nmap when it is installed (nmap -sn / nmap -sV); otherwise falls back to
 * a built-in TCP connect scan with banner grabbing on common IoT ports. */
require_once __DIR__ . '/checks.php';

const IOT_PORTS = [21, 22, 23, 80, 443, 554, 1883, 5683, 8008, 8080, 8443, 8883, 9999];

function validate_range(string $cidr): ?array {
    if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/', trim($cidr), $m)) return null;
    $ip = $m[1]; $prefix = (int)$m[2];
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $prefix < 24 || $prefix > 32) return null;
    $n = ip2long($ip);
    $private = [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['127.0.0.0', 8]];
    $ok = false;
    foreach ($private as [$net, $bits]) {
        $mask = -1 << (32 - $bits);
        if (($n & $mask) === (ip2long($net) & $mask)) $ok = true;
    }
    if (!$ok) return null;                       // scanning restricted to private testbed ranges
    $mask = -1 << (32 - $prefix);
    $first = ($n & $mask); $last = $first + (1 << (32 - $prefix)) - 1;
    $hosts = [];
    for ($i = ($prefix < 31 ? $first + 1 : $first); $i <= ($prefix < 31 ? $last - 1 : $last); $i++) $hosts[] = long2ip($i);
    return $hosts;
}

function probe(string $ip, int $port, float $timeout = 0.4): ?string {
    $fp = @stream_socket_client("tcp://$ip:$port", $errno, $errstr, $timeout);
    if (!$fp) return null;
    stream_set_timeout($fp, 1);
    $banner = '';
    if (in_array($port, [21, 22, 23])) {
        $banner = (string) @fread($fp, 512);
    } elseif ($port === 554) {
        fwrite($fp, "OPTIONS rtsp://$ip/ RTSP/1.0\r\nCSeq: 1\r\n\r\n");
        $banner = (string) @fread($fp, 1024);
    } elseif ($port === 1883) {
        fwrite($fp, "\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04scan");   // CONNECT, no username/password
        $banner = bin2hex((string) @fread($fp, 4));
    } else {
        fwrite($fp, "GET / HTTP/1.0\r\nHost: $ip\r\n\r\n");
        $banner = (string) @stream_get_contents($fp, 4096);
    }
    fclose($fp);
    return $banner;
}

function http_get(string $ip, int $port, string $path, ?string $auth = null): string {
    $fp = @stream_socket_client("tcp://$ip:$port", $e, $s, 1);
    if (!$fp) return '';
    $h = "GET $path HTTP/1.0\r\nHost: $ip\r\n" . ($auth ? 'Authorization: Basic ' . base64_encode($auth) . "\r\n" : '') . "\r\n";
    fwrite($fp, $h); stream_set_timeout($fp, 1);
    $r = (string) stream_get_contents($fp, 8192); fclose($fp);
    return $r;
}

function ftp_anonymous(string $ip): bool {
    $fp = @stream_socket_client("tcp://$ip:21", $e, $s, 1);
    if (!$fp) return false;
    stream_set_timeout($fp, 2);
    fgets($fp); fwrite($fp, "USER anonymous\r\n"); fgets($fp);
    fwrite($fp, "PASS scanner@testbed.local\r\n"); $r = (string) fgets($fp);
    fwrite($fp, "QUIT\r\n"); fclose($fp);
    return strpos($r, '230') === 0;
}

function device_name(array $banners): string {
    foreach ($banners as $b) {
        if (preg_match('/<title>([^<]+)<\/title>/i', $b, $m)) return trim($m[1]);
        if (preg_match('/"device"\s*:\s*"([^"]+)"/', $b, $m)) return $m[1];
        if (preg_match('/"name"\s*:\s*"([^"]+)"/', $b, $m)) return $m[1];
        if (preg_match('/^220 (.+?) FTP/m', $b, $m)) return trim($m[1]);
    }
    return 'Unknown IoT device';
}

/* Returns [ ['ip'=>..., 'name'=>..., 'ports'=>[...], 'findings'=>[rule_key=>evidence]] ] */
function run_network_scan(array $hosts): array {
    $results = [];
    foreach ($hosts as $ip) {
        $open = [];
        foreach (IOT_PORTS as $p) {
            $b = probe($ip, $p);
            if ($b !== null) $open[$p] = $b;
        }
        if (!$open) continue;                     // host not live / no IoT service
        $f = [];
        if (isset($open[23])) $f['telnet_open'] = 'Port 23/tcp open: ' . trim(preg_replace('/\s+/', ' ', substr($open[23], 0, 80)));
        if (isset($open[21])) {
            $f['ftp_cleartext'] = 'Port 21/tcp: ' . trim(strtok($open[21], "\r\n"));
            if (ftp_anonymous($ip)) $f['ftp_anonymous'] = 'USER anonymous accepted (230 Login successful)';
            if (preg_match('/vsFTPd 2\.3\.4/i', $open[21])) $f['outdated_component'] = 'vsFTPd 2.3.4 (2011 release)';
        }
        if (isset($open[554]) && strpos($open[554], 'RTSP/1.0 200') === 0) $f['rtsp_no_auth'] = 'OPTIONS on 554/tcp answered 200 OK without credentials';
        if (isset($open[1883]) && $open[1883] === '20020000') $f['mqtt_no_auth'] = 'CONNECT without credentials returned CONNACK 0 (accepted)';
        foreach ([80, 8008, 8080] as $hp) {
            if (!isset($open[$hp])) continue;
            $f['http_cleartext'] = ($f['http_cleartext'] ?? 'Plain HTTP on') . " $hp/tcp";
            if (strpos($open[$hp], '401') !== false) {
                $r = http_get($ip, $hp, '/', 'admin:admin');
                if (strpos($r, '200 OK') !== false) { $f['http_default_creds'] = "HTTP Basic auth admin:admin accepted on $hp/tcp"; $open['auth_' . $hp] = $r; }
            }
            if (preg_match('/"relay_state"/', $open[$hp]) || strpos(http_get($ip, $hp, '/api/relay'), '"relay_state"') !== false) {
                if (strpos(http_get($ip, $hp, '/api/relay'), '200 OK') !== false) $f['http_no_auth'] = "GET /api/relay on $hp/tcp returned device state without credentials";
            }
            $info = http_get($ip, $hp, '/setup/eureka_info');
            if (strpos($info, '200 OK') !== false && strpos($info, 'build_version') !== false) $f['info_disclosure'] = "GET /setup/eureka_info on $hp/tcp returned build_version, MAC and SSID";
            if (preg_match('/Server: (lighttpd\/1\.4\.(?:[0-3]?\d)|Mongoose\/[0-6]\.\d)\b/i', $open[$hp], $m)) $f['outdated_component'] = "Server banner: {$m[1]}";
        }
        $ports = array_values(array_filter(array_keys($open), 'is_int'));
        $named = $open; krsort($named, SORT_STRING);          // authenticated pages first
        $results[] = ['ip' => $ip, 'name' => device_name($named), 'ports' => $ports, 'findings' => $f];
    }
    return $results;
}
