![GitHub stars](https://img.shields.io/github/stars/Shaamak/Web-Application-Firewall?style=social)
![GitHub forks](https://img.shields.io/github/forks/Shaamak/Web-Application-Firewall?style=social)

# 🛡️ Basic Web Application Firewall (WAF)

A lightweight, rule-based Web Application Firewall built with Python and Flask that detects and blocks common web attacks including SQL Injection, XSS, Path Traversal, and Command Injection.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🎯 Features

- **Real-time Attack Detection**: Inspects HTTP requests in real-time using regex-based pattern matching
- **Multiple Attack Vectors**: Detects SQL Injection, Cross-Site Scripting (XSS), Path Traversal, and Command Injection
- **Reverse Proxy Architecture**: Sits between users and the backend application transparently
- **Attack Logging**: Comprehensive logging of all detected attacks with timestamps and details
- **Dashboard Interface**: Simple web dashboard to monitor WAF status
- **Zero Dependencies on External Services**: Runs completely offline with no external API calls

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository**
```bash
   git clone https://github.com/yourusername/basic-waf.git
   cd basic-waf
```

2. **Create a virtual environment**
```bash
   python -m venv venv
   
   # Activate on Windows
   venv\Scripts\activate
   
   # Activate on Mac/Linux
   source venv/bin/activate
```

3. **Install dependencies**
```bash
   pip install -r requirements.txt
```

### Running the WAF

The project consists of two components that need to run simultaneously:

**Terminal 1 - Start the vulnerable backend application:**
```bash
python vulnerable_app.py
```
This starts the backend on `http://127.0.0.1:5001`

**Terminal 2 - Start the WAF:**
```bash
python waf.py
```
This starts the WAF on `http://127.0.0.1:5000`

Now access your application through the WAF at: **http://127.0.0.1:5000**

## 🧪 Testing the WAF

### Legitimate Request (✅ Allowed)
```
http://127.0.0.1:5000/search?q=hello
```

### SQL Injection Attack (❌ Blocked)
```
http://127.0.0.1:5000/user?id=1' OR '1'='1
http://127.0.0.1:5000/search?q=test' UNION SELECT * FROM users--
```

### XSS Attack (❌ Blocked)
```
http://127.0.0.1:5000/search?q=<script>alert('xss')</script>
http://127.0.0.1:5000/?name=<img src=x onerror=alert(1)>
```

### Path Traversal Attack (❌ Blocked)
```
http://127.0.0.1:5000/files?path=../../etc/passwd
http://127.0.0.1:5000/files?path=..\..\windows\system32
```

### Command Injection Attack (❌ Blocked)
```
http://127.0.0.1:5000/search?q=test; ls -la
http://127.0.0.1:5000/?cmd=cat /etc/passwd
```

## 📊 WAF Dashboard

Access the monitoring dashboard at:
```
http://127.0.0.1:5000/waf/dashboard
```

The dashboard shows:
- WAF status
- Active detection rules
- Log file location
- Quick test links

## 📁 Project Structure
```
waf-project/
├── waf.py                 # Main WAF application (reverse proxy)
├── vulnerable_app.py      # Intentionally vulnerable backend app
├── requirements.txt       # Python dependencies
├── .gitignore            # Git ignore rules
├── README.md             # Project documentation
└── logs/                 # Attack logs (auto-created)
    └── attacks_YYYYMMDD.log
```

## 🔍 How It Works

### Architecture
```
User Request → WAF (Port 5000) → Inspection → Decision
                                     ↓
                              ┌──────┴──────┐
                              ↓             ↓
                         Malicious?      Safe?
                              ↓             ↓
                         Block + Log    Forward → Backend (Port 5001)
```

### Detection Mechanism

1. **Request Interception**: All incoming HTTP requests are intercepted by the WAF
2. **Parameter Extraction**: Extracts data from query parameters, form data, JSON body, and URL path
3. **Pattern Matching**: Checks each parameter against regex patterns for known attack signatures
4. **Decision Making**: 
   - If malicious → Returns 403 Forbidden and logs the attack
   - If safe → Forwards request to backend application
5. **Response Forwarding**: Returns backend's response to the user

### Detection Rules

The WAF uses regex-based pattern matching to detect:

- **SQL Injection**: `UNION SELECT`, `OR 1=1`, `DROP TABLE`, SQL comments, etc.
- **XSS**: `<script>` tags, event handlers (`onerror`, `onload`), `javascript:` protocol
- **Path Traversal**: `../`, `..\\`, encoded variants, system file paths
- **Command Injection**: Shell operators (`;`, `|`, `&&`), command execution patterns

## 📝 Attack Logs

All blocked attacks are logged to `logs/attacks_YYYYMMDD.log` with:
```json
{
  "timestamp": "2025-01-13 14:30:45",
  "attack_type": "SQL Injection",
  "ip": "127.0.0.1",
  "method": "GET",
  "url": "http://127.0.0.1:5000/user?id=1' OR '1'='1",
  "details": {
    "parameter": "id",
    "value": "1' OR '1'='1",
    "pattern": "(\\bor\\b\\s+\\d+=\\d+)"
  }
}
```

## ⚙️ Configuration

Edit `waf.py` to customize:
```python
# Backend application URL
BACKEND_URL = "http://127.0.0.1:5001"

# Log directory
LOG_DIR = "logs"

# Add custom detection patterns to:
SQL_INJECTION_PATTERNS = [...]
XSS_PATTERNS = [...]
PATH_TRAVERSAL_PATTERNS = [...]
COMMAND_INJECTION_PATTERNS = [...]
```

## 🎓 Educational Purpose

This WAF is designed for **educational and demonstration purposes**. It showcases:

- Reverse proxy concepts
- Request inspection techniques
- Regex-based pattern matching
- Attack detection and logging
- Basic cybersecurity principles


## 🛠️ Future Enhancements

Potential improvements for learning:

- [ ] Machine learning-based detection
- [ ] Rate limiting and IP blocking
- [ ] Whitelist/blacklist functionality
- [ ] Custom rule configuration via JSON/YAML
- [ ] Web-based management interface
- [ ] Anomaly detection for zero-day attacks
- [ ] Integration with threat intelligence feeds
- [ ] Async request handling for better performance

## 📚 Learning Resources

To understand more about web security:

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/)
- [Web Application Firewall Evaluation Criteria](https://owasp.org/www-community/Web_Application_Firewall)

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🙏 Acknowledgments

- Flask framework for making Python web development simple
- OWASP for comprehensive web security resources
- The cybersecurity community for sharing knowledge

---

**⭐ If you found this project helpful for learning, please give it a star!**

**🐛 Found a bug or have a suggestion? Open an issue!**

**📖 Want to learn more? Check out the code and comments!**
