# IoT Security Assessment Framework

Multi-layer vulnerability assessment for smart home IoT devices (network, firmware, hardware, intrusion detection) with CVSS v3.1 scoring, CWE and MITRE ATT&CK mapping.

## Quick start (portable demo, SQLite)
```
python3 testbed/emulated_devices.py &                      # five emulated devices on 127.0.10.11-15
python3 testbed/build_sample_firmware.py testbed/sample_camera_firmware_v2.3.4.tar.gz
php setup.php analyst "ChooseAStrongPassword1!"            # creates tables + analyst account
python3 ml/ids_model.py data/flows.csv data/iot_security.sqlite   # trains the IDS (synthetic flows)
php -S 127.0.0.1:8099                                      # open http://127.0.0.1:8099
```
Then log in, scan `127.0.10.0/24`, and upload the sample firmware for the IP camera.

## MySQL deployment
`mysql -u root -p < database/schema_mysql.sql`, then set `DB_DRIVER=mysql` and `DB_PASS` in the web server environment and run `php setup.php`.

Requirements: PHP 8.1+ (pdo_sqlite or pdo_mysql), Python 3.10+ with pandas, numpy, scikit-learn, joblib (xgboost optional), Nmap and binwalk optional.

`data/flows.csv` is SYNTHETIC. Replace it with flows from real captures before reporting results.
