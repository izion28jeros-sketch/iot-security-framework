"""Builds a sample firmware image (tar.gz root file system) for the emulated
IP camera so the firmware analysis module can be demonstrated.
Real firmware is first unpacked with binwalk; this sample is already a tarball."""
import io, os, sys, tarfile, time
files = {
 "etc/passwd": "root:x:0:0:root:/root:/bin/sh\nadmin:x:500:500::/home/admin:/bin/sh\n",
 "etc/shadow": "root:$1$abcd1234$Xh7wG2JQe5Qz1aV8nQ6xW1:18000:0:99999:7:::\nadmin:$1$efgh5678$k9QpP3ZcW2r4tYb7nL0vE.:18000:0:99999:7:::\n",
 "etc/config/system.conf": "device_model=EmuCam-1080\nfw_version=2.3.4\nadmin_user=admin\nadmin_password=admin123\ncloud_api_key=EXAMPLE-ONLY-0000\n",
 "etc/init.d/rcS": "#!/bin/sh\nmount -a\n/usr/sbin/telnetd -l /bin/sh &\n/usr/sbin/lighttpd -f /etc/lighttpd.conf\n/usr/bin/rtspd &\n",
 "etc/ssl/private/device.key": "-----BEGIN RSA PRIVATE KEY-----\nTUlJRUVYQU1QTEVPTkxZTk9UQVJFQUxLRVk=\n-----END RSA PRIVATE KEY-----\n",
 "usr/bin/fw_update.sh": "#!/bin/sh\n# download and flash new firmware\nwget -O /tmp/fw.bin $1\nif [ \"$(md5sum /tmp/fw.bin | cut -d' ' -f1)\" = \"$2\" ]; then\n  mtd write /tmp/fw.bin firmware\nfi\n",
 "lib/libssl.so.1.0.0": "\x7fELF....OpenSSL 1.0.2k  26 Jan 2017....",
 "bin/busybox": "\x7fELF....BusyBox v1.24.1 (2016-03-04 10:12:33 CST)....",
 "www/index.html": "<html><title>EmuCam</title></html>\n",
}
out = sys.argv[1] if len(sys.argv) > 1 else "sample_camera_firmware_v2.3.4.tar.gz"
with tarfile.open(out, "w:gz") as tar:
    for name, content in files.items():
        data = content.encode("latin-1")
        ti = tarfile.TarInfo(name); ti.size = len(data); ti.mtime = int(time.time())
        ti.mode = 0o755 if name.endswith((".sh", "rcS")) or name.startswith("bin/") else 0o644
        tar.addfile(ti, io.BytesIO(data))
print(out)
