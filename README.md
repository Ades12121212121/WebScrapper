# WebScannerX 🛡️

A powerful and comprehensive web security scanner. WebScannerX provides advanced scanning capabilities for web applications, including port scanning, vulnerability detection, and security analysis.

## 🚀 Features

- 🔍 **Comprehensive Port Scanning**
  - Customizable ranges
  - Service detection
  - Version analysis

- 🛡️ **Advanced Security Analysis**
  - SQLi vulnerability detection
  - XSS analysis
  - CSRF verification
  - Directory traversal scanning

- 📊 **Detailed Reporting**
  - Interactive HTML reports
  - Visual analysis
  - Executive summary
  - Mitigation recommendations

- 🛠️ **Flexible Configuration**
  - Stealth mode
  - Rate limiting
  - Customizable timeouts
  - Proxy support

- 🎨 **Enhanced Console Interface**
  - Color-coded output
  - Progress indicators
  - Data tables
  - Formatted messages

## 📦 Usage

### Command Line Options

```bash
# Scan a target
WebScannerX.exe scan <target>

# Configure settings
WebScannerX.exe config <option> <value>

# Stealth mode
WebScannerX.exe mode stealth

# Set timeout
WebScannerX.exe timeout 30

# View help
WebScannerX.exe help
```

### Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| max_threads | Concurrent threads | 10 |
| port_range | Port range | 1-1000 |
| user_agent | User agent | "Mozilla/5.0" |
| proxy | Proxy server | "http://proxy:8080" |
| rate_limit | Rate limit | 10 |
| ssl_verify | SSL verification | true/false |
| dns_timeout | DNS timeout | 5 |
| sql_scan | SQLi scanning | true/false |
| xss_scan | XSS scanning | true/false |
| csrf_scan | CSRF scanning | true/false |
| dir_scan | Directory traversal scanning | true/false |
| cookie_scan | Cookie security scanning | true/false |
| session_scan | Session security scanning | true/false |
| cipher_scan | SSL/TLS cipher scanning | true/false |
| header_scan | Security header scanning | true/false |

## 📈 Example Report

The generated HTML report includes:
- Executive summary
- Vulnerability analysis
- Scanner configuration
- Mitigation recommendations
- Charts and visualizations

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Support

For support:
- Open an issue in the GitHub repository
- Contact the development team
- Consult the complete documentation

## 🤝 Contributing

Contributions are welcome! Please submit a Pull Request.

## 🛡️ Security

If you discover any security issues, please report them responsibly.

## 🙏 Acknowledgments

- Thanks to all contributors and testers
- Thanks to the open-source community for the libraries used
- Thanks to users who help us improve
