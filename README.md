# DaisyScan - Web Security Scanner

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Flask](https://img.shields.io/badge/flask-2.3.3-red)
![License](https://img.shields.io/badge/license-MIT-orange)

DaisyScan is a comprehensive web security scanning tool built with Flask that helps security professionals and developers identify potential vulnerabilities in web applications. It features multi-threaded scanning capabilities with extensive payload databases for subdomain enumeration, sensitive file discovery, SQL injection testing, and SSRF vulnerability detection.

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 🔍 Subdomain Enumeration | Discover subdomains using an extensive wordlist (200+ common subdomains) |
| 📁 Sensitive Path Discovery | Scan for exposed configuration files, backups, and sensitive documents |
| 💉 SQL Injection Testing | Test endpoints with 20+ SQL injection payloads |
| 🌐 SSRF Vulnerability Detection | Check for Server-Side Request Forgery with 25+ payloads |
| 🔐 Authentication Bypass Testing | Test common authentication bypass headers |
| ⚡ Multi-threaded Architecture | Fast concurrent scanning with ThreadPoolExecutor |
| 📊 Real-time Results | Live scanning results with severity classification |
| 🎯 Custom Endpoint Scanning | Scan specific API endpoints and common web paths |

## 📋 Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.8 or higher |
| pip | Latest |
| Git | Optional |

## 🛠️ Installation 

```
git clone https://github.com/yourusername/DaisyScan.git
cd DaisyScan

```
cd DaisyScan-
```

```
pip3 install -r requirements.txt
```

```
python3 DaisyScan.py
```

 


