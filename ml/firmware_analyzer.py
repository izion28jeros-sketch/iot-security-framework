"""Firmware analysis module (Module 2).
Extracts a firmware image and searches the file system for weaknesses.
- tar/tar.gz root file systems are extracted with Python's tarfile (safe 'data' filter);
- other images (.bin, SquashFS, etc.) are extracted with binwalk -e when binwalk is installed.
Prints a JSON report: {"files": n, "fw_version": "...", "findings": [{"rule":..., "evidence":...}]}"""
import json, os, re, shutil, subprocess, sys, tarfile, tempfile

def extract(path, out):
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as t:
            t.extractall(out, filter="data")
        return "tarfile"
    if shutil.which("binwalk"):
        subprocess.run(["binwalk", "-e", "-q", "-C", out, path], check=False, timeout=600)
        return "binwalk"
    raise SystemExit(json.dumps({"error": "Image is not a tar archive and binwalk is not installed."}))

def analyse(path):
    out = tempfile.mkdtemp(prefix="fw_")
    method = extract(path, out)
    findings, files, version = [], 0, None
    def add(rule, ev):
        if not any(f["rule"] == rule for f in findings):
            findings.append({"rule": rule, "evidence": ev})
    for root, _, names in os.walk(out):
        for n in names:
            p = os.path.join(root, n); rel = os.path.relpath(p, out); files += 1
            try:
                data = open(p, "rb").read(2_000_000).decode("latin-1")
            except OSError:
                continue
            if rel.endswith("etc/shadow"):
                weak = [l.split(":")[0] for l in data.splitlines() if re.match(r"^[^:]+:\$1\$", l)]
                if weak: add("fw_hardcoded_hash", f"{rel}: MD5-crypt hashes for accounts {', '.join(weak)}")
            m = re.search(r"^(\w*(?:password|passwd|api_key|secret)\w*)\s*=\s*(\S+)", data, re.I | re.M)
            if m and not rel.endswith("shadow"):
                add("fw_plaintext_secret", f"{rel}: {m.group(1)}=*** (value stored in plaintext)")
            if "BEGIN RSA PRIVATE KEY" in data or "BEGIN EC PRIVATE KEY" in data or "BEGIN PRIVATE KEY" in data:
                add("fw_private_key", f"{rel}: PEM private key block")
            if re.search(r"telnetd\b.*-l\s*/bin/sh", data):
                add("fw_telnet_enabled", f"{rel}: telnetd started with -l /bin/sh")
            if re.search(r"md5sum", data) and re.search(r"mtd write|flash|sysupgrade", data) and not re.search(r"openssl\s+dgst|verify|signature", data, re.I):
                add("fw_unsigned_update", f"{rel}: image flashed after MD5 comparison only")
            m = re.search(r"OpenSSL (1\.0\.\d\w?|1\.1\.0\w?)", data)
            if m: add("fw_outdated_lib", f"{rel}: OpenSSL {m.group(1)} (end of life)")
            m = re.search(r"fw_version=(\S+)", data)
            if m: version = m.group(1)
    if files:
        add("fw_not_encrypted", f"Extracted {files} files with {method}; no decryption step required")
    shutil.rmtree(out, ignore_errors=True)
    return {"files": files, "method": method, "fw_version": version, "findings": findings}

if __name__ == "__main__":
    print(json.dumps(analyse(sys.argv[1])))
