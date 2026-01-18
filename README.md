# 🔍 WebVersionScanner v1.0

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0-blue?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" alt="Python Logo" width="100">
</p>

---

```
================================================================================
                      WebVersionScanner v1.0
================================================================================

  Created by: Michele Gramegna

  CONTACT & FOLLOW:
  [*] GitHub: https://github.com/gramegnamichele
  [*] LinkedIn: https://www.linkedin.com/in/michele-gramegna-61a0773a6/

================================================================================
```

## 📖 Overview

**WebVersionScanner** is an advanced Python tool for detecting software versions running on websites. It uses multiple detection techniques and bypass mechanisms to identify CMS platforms, frameworks, libraries, server software, and technologies even on hardened/secured websites.

## ✨ Features

### 🎯 Detection Capabilities
- **CMS Detection**: WordPress, Drupal, Joomla, Magento, PrestaShop, OpenCart
- **Server Software**: Apache, Nginx, cPanel
- **Programming Languages**: PHP, Python, Java, Ruby, Node.js, ASP.NET
- **JavaScript Frameworks**: React, Angular, Vue.js, Next.js, Nuxt.js, Gatsby, Svelte, Astro
- **JavaScript Libraries**: jQuery, Bootstrap, jQuery UI
- **Backend Frameworks**: Express, Django, Flask
- **Services**: phpMyAdmin, Google Cloud, CDN providers (Cloudflare, AWS, Akamai, Fastly)

### 🔬 Advanced Detection Techniques (21 methods)
1. **HTTP Headers Analysis** - Server and software identification from headers
2. **Meta Tags & Comments Scanning** - Extract version info from HTML comments
3. **robots.txt Pattern Detection** - Identify CMS via robots.txt patterns
4. **sitemap.xml Analysis** - Detect platforms from sitemap structure
5. **Favicon Fingerprinting** - Hash-based software identification
6. **API Endpoint Discovery** - Test for known API endpoints
7. **Static Files Patterns** - Check for characteristic directory structures
8. **Error Page Analysis** - Identify software from error pages
9. **Backup File Detection** - Scan for .bak, .zip, .tar.gz files
10. **Package Manager Files** - Find package.json, composer.json, Gemfile, requirements.txt
11. **Hardened CMS Detection** - Advanced fingerprinting for hidden/hardened installations
12. **Security Headers Inspection** - Analyze security-related headers
13. **JavaScript Analytics Fingerprinting** - Detect from analytics scripts
14. **DNS Records Analysis** - Check MX and DNS records
15. **JavaScript Source Maps** - Detect frameworks from source maps
16. **CDN Headers Detection** - Identify CDN services
17. **SSL Certificate Analysis** - Extract info from SSL certificates
18. **HTTP Methods Enumeration** - Test for WebDAV and misconfigurations
19. **Directory Listing Detection** - Scan for exposed directories
20. **Framework Fingerprinting Database** - Identify modern frameworks
21. **Cookie Analysis** - Detect software from session cookies
22. **Response Time Analysis** - Timing attack to identify real paths

### 📊 Version Comparison
- Compares detected versions against latest known versions
- Identifies outdated software with security risks
- Shows specific version numbers with risk assessment

## 🚀 Installation

### Prerequisites
- Python 3.7+
- pip (Python package manager)

### Setup

1. Clone or download the repository:
```bash
cd WebSoftwareScanner
```

2. Install required dependencies:
```bash
pip install requests
```

3. Make the script executable (optional):
```bash
# On Linux/Mac
chmod +x version_scanner.py

# On Windows - already executable
```

## 💻 Usage

### Basic Usage

Run the scanner with a website URL:

```bash
python version_scanner.py
```

Then enter the target URL when prompted:
```
Enter the website URL to scan: example.com
```

### Examples

#### Scan with HTTP
```bash
python version_scanner.py
# Enter: http://example.com
```

#### Scan with HTTPS
```bash
python version_scanner.py
# Enter: https://example.com
```

#### Scan without protocol (defaults to HTTPS)
```bash
python version_scanner.py
# Enter: example.com
```

## 📋 Output

The scanner provides comprehensive reports including:

### Detection Results
```
DETECTED SOFTWARE AND VERSIONS:
----------------------------------------------------------------------

[!] OUTDATED - jQuery
  Detected Version: 1.8.2
  Latest Version:   3.7.1
  Risk Level:       HIGH - Requires immediate update

[+] UP-TO-DATE - WordPress
  Current Version: 6.9

[*] DETECTED - Apache
  Version: 2.4.50
```

### Scan Summary
- Total software detected
- Number of up-to-date components
- Number of outdated components
- Detection methods used

### Recommendations
- Security update priorities
- Best practices for updates
- Compatibility testing guidelines

## 🛠️ Supported Software

### CMS Platforms
- WordPress
- Drupal
- Joomla
- Magento
- PrestaShop
- OpenCart

### Web Servers
- Apache
- Nginx
- IIS

### Control Panels
- cPanel
- Plesk

### Backend Languages
- PHP
- Python
- Java
- Ruby
- Node.js

### Frameworks
- Express
- Django
- Flask
- ASP.NET
- Tomcat

### Frontend Frameworks
- React
- Angular
- Vue.js
- Next.js
- Nuxt.js
- Gatsby
- Svelte
- Astro

### Libraries
- jQuery
- Bootstrap
- jQuery UI

### Services
- phpMyAdmin
- Google Cloud
- AWS
- Cloudflare
- Akamai
- Fastly

## ⚠️ Security & Disclaimer

**Legal Notice**: This tool is designed for authorized security assessments and penetration testing only. 

- Only scan websites you own or have explicit written permission to test
- Unauthorized scanning may violate laws in your jurisdiction
- Use responsibly and ethically
- The author is not liable for misuse of this tool

## ⚙️ How It Works

The scanner performs multiple scanning phases:

1. **Initial Reconnaissance** - Fetches website content and headers
2. **Standard Detection** - Checks basic CMS/server indicators
3. **Advanced Detection** - Uses specialized fingerprinting techniques
4. **Bypass Techniques** - Tests hardened/secured installations
5. **Version Analysis** - Compares versions against known latest versions
6. **Report Generation** - Creates comprehensive security report

## 🏆 Features & Benefits

✅ **Multi-layered Detection** - 22 different detection techniques  
✅ **Bypass Hardening** - Works on secured/hardened websites  
✅ **Version Tracking** - Knows latest versions for major software  
✅ **Risk Assessment** - Identifies outdated software  
✅ **Fast Scanning** - Efficient multi-method approach  
✅ **Comprehensive Reports** - Detailed findings with recommendations  
✅ **No Installation Required** - Stand-alone Python script  
✅ **Ethical Design** - Clear security disclaimers and guidelines  

## 🔧 Troubleshooting

### SSL Certificate Warnings
The tool ignores SSL certificate warnings to scan HTTPS sites with self-signed certificates. This is intentional for penetration testing.

### Connection Timeouts
If scanning takes too long:
- Check your internet connection
- Target website might be slow or blocking requests
- Try again with the same URL

### No Software Detected
- Website might be heavily hardened
- Might be a static HTML site with no CMS
- Server might block fingerprinting attempts

## 📈 Performance

- **Scanning Time**: 10-30 seconds per website (depends on website size and speed)
- **Memory Usage**: Minimal (~50MB)
- **CPU Usage**: Low
- **Concurrent Scans**: Run multiple instances for batch scanning

## ⛔ Limitations

- Cannot detect custom/proprietary software
- Some hardened installations may evade detection
- WAF/security tools might block detection methods
- Requires network access to target website
- Some frameworks automatically hide version info

## 📜 License

This tool is provided as-is for authorized security testing only.

## 🤝 Contributing

Found a bug? Have suggestions? Want to contribute?

- Open issues on GitHub
- Submit pull requests
- Suggest new detection methods
- Report false positives/negatives

## 👨‍💻 Author & Credits

**Credit**: [github.com/gramegnamichele](https://github.com/gramegnamichele)

### 📬 Connect With Me

<p align="left">
  <a href="https://github.com/gramegnamichele">
    <img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub">
  </a>
  <a href="https://www.linkedin.com/in/michele-gramegna-61a0773a6/">
    <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn">
  </a>
</p>

## ⭐ Support

If you find this tool useful, please:
- Star the repository
- Follow on social media
- Share with others
- Submit improvements

## 📢 Disclaimer

This tool is provided for educational and authorized testing purposes only. Unauthorized access to computer systems is illegal. Always obtain written permission before testing any website or system you do not own.

---

**Version**: 1.0  
**Last Updated**: January 14, 2026  
**Status**: Active Development  
