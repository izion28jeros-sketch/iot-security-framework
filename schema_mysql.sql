-- MySQL schema for the IoT Security Assessment Framework (database: iot_security)
CREATE DATABASE IF NOT EXISTS iot_security CHARACTER SET utf8mb4;
USE iot_security;
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('analyst','homeowner') NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE scans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  network_range VARCHAR(20) NOT NULL,
  scan_type VARCHAR(30) NOT NULL,
  started_at DATETIME NOT NULL,
  ended_at DATETIME NULL,
  hosts_found INT DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE devices (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL UNIQUE,
  mac_address VARCHAR(17) NULL,
  device_name VARCHAR(100) NOT NULL,
  category VARCHAR(40) NULL,
  open_ports VARCHAR(255) NULL,
  firmware_version VARCHAR(50) NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'Active',
  scan_date DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE vulnerabilities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NOT NULL,
  scan_id INT NULL,
  rule_key VARCHAR(40) NOT NULL,
  vulnerability VARCHAR(255) NOT NULL,
  layer ENUM('network','firmware','hardware') NOT NULL,
  evidence TEXT NULL,
  cwe_id VARCHAR(15) NULL,
  cvss_vector VARCHAR(60) NOT NULL,
  cvss_score DECIMAL(3,1) NOT NULL,
  risk_level VARCHAR(10) NOT NULL,
  attack_technique VARCHAR(20) NULL,
  recommendation TEXT NOT NULL,
  status VARCHAR(15) NOT NULL DEFAULT 'Open',
  found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_device_rule (device_id, rule_key),
  FOREIGN KEY (device_id) REFERENCES devices(id),
  FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE ids_runs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  run_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  model VARCHAR(60) NOT NULL,
  dataset VARCHAR(120) NOT NULL,
  n_train INT, n_test INT,
  accuracy DECIMAL(6,4), fpr DECIMAL(6,4),
  latency_ms_per_1000 DECIMAL(8,2),
  per_class_json TEXT
);
CREATE TABLE ids_alerts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  alert_time DATETIME NOT NULL,
  source_ip VARCHAR(45) NOT NULL,
  dest_ip VARCHAR(45) NOT NULL,
  attack_type VARCHAR(30) NOT NULL,
  confidence DECIMAL(5,4) NOT NULL
);
