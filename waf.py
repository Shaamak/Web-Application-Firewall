from flask import Flask, request, jsonify, Response
import requests
import re
import json
import os
from datetime import datetime
from urllib.parse import unquote

app = Flask(__name__)

# Configuration
BACKEND_URL = "http://127.0.0.1:5001"  # Our vulnerable app
LOG_DIR = "logs"

# Create logs directory if it doesn't exist
os.makedirs(LOG_DIR, exist_ok=True)

# ============================================
# DETECTION RULES
# ============================================

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    r"(\bunion\b.*\bselect\b)",
    r"(\bselect\b.*\bfrom\b)",
    r"(\binsert\b.*\binto\b)",
    r"(\bdelete\b.*\bfrom\b)",
    r"(\bdrop\b.*\btable\b)",
    r"(\bupdate\b.*\bset\b)",
    r"(--|\#|\/\*)",  # SQL comments
    r"(\bor\b\s+\d+=\d+)",
    r"(\band\b\s+\d+=\d+)",
    r"('\s+or\s+'1'\s*=\s*'1)",
    r"('\s+or\s+1\s*=\s*1)",
    r"(;\s*drop\s+table)",
    r"(exec\s*\()",
    r"(execute\s+immediate)",
]

# XSS (Cross-Site Scripting) patterns
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"<iframe[^>]*>",
    r"<object[^>]*>",
    r"<embed[^>]*>",
    r"eval\s*\(",
    r"expression\s*\(",
    r"<img[^>]*onerror",
    r"<svg[^>]*onload",
]

# Path Traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e/",
    r"%2e%2e\\",
    r"\.\.%2f",
    r"/etc/passwd",
    r"/etc/shadow",
    r"c:\\windows",
    r"c:/windows",
]

# Command Injection patterns
COMMAND_INJECTION_PATTERNS = [
    r";\s*ls\s",
    r";\s*cat\s",
    r";\s*rm\s",
    r"\|\s*ls\s",
    r"\|\s*cat\s",
    r"&&\s*ls\s",
    r"&&\s*cat\s",
    r"`.*`",
    r"\$\(.*\)",
]

# ============================================
# DETECTION FUNCTIONS
# ============================================

def check_sql_injection(value):
    """Check if the value contains SQL injection patterns"""
    value_lower = value.lower()
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return True, pattern
    return False, None

def check_xss(value):
    """Check if the value contains XSS patterns"""
    value_lower = value.lower()
    for pattern in XSS_PATTERNS:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return True, pattern
    return False, None

def check_path_traversal(value):
    """Check if the value contains path traversal patterns"""
    # Decode URL encoding
    decoded_value = unquote(value)
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, decoded_value, re.IGNORECASE):
            return True, pattern
    return False, None

def check_command_injection(value):
    """Check if the value contains command injection patterns"""
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True, pattern
    return False, None

# ============================================
# REQUEST INSPECTION
# ============================================

def inspect_request():
    """
    Inspect the incoming request for malicious patterns
    Returns: (is_malicious, attack_type, details)
    """
    # Get all parameters from the request
    all_params = {}
    
    # Query parameters
    all_params.update(request.args.to_dict())
    
    # Form data
    if request.form:
        all_params.update(request.form.to_dict())
    
    # JSON body
    if request.is_json:
        try:
            json_data = request.get_json()
            if isinstance(json_data, dict):
                all_params.update(json_data)
        except:
            pass
    
    # Check URL path itself
    url_path = request.path
    
    # Inspect each parameter
    for param_name, param_value in all_params.items():
        param_value_str = str(param_value)
        
        # Check for SQL Injection
        is_sqli, pattern = check_sql_injection(param_value_str)
        if is_sqli:
            return True, "SQL Injection", {
                "parameter": param_name,
                "value": param_value_str,
                "pattern": pattern
            }
        
        # Check for XSS
        is_xss, pattern = check_xss(param_value_str)
        if is_xss:
            return True, "Cross-Site Scripting (XSS)", {
                "parameter": param_name,
                "value": param_value_str,
                "pattern": pattern
            }
        
        # Check for Path Traversal
        is_path_traversal, pattern = check_path_traversal(param_value_str)
        if is_path_traversal:
            return True, "Path Traversal", {
                "parameter": param_name,
                "value": param_value_str,
                "pattern": pattern
            }
        
        # Check for Command Injection
        is_cmd_injection, pattern = check_command_injection(param_value_str)
        if is_cmd_injection:
            return True, "Command Injection", {
                "parameter": param_name,
                "value": param_value_str,
                "pattern": pattern
            }
    
    # Check URL path for path traversal
    is_path_traversal, pattern = check_path_traversal(url_path)
    if is_path_traversal:
        return True, "Path Traversal", {
            "parameter": "URL Path",
            "value": url_path,
            "pattern": pattern
        }
    
    return False, None, None

# ============================================
# LOGGING
# ============================================

def log_attack(attack_type, details):
    """Log detected attacks to a file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_entry = {
        "timestamp": timestamp,
        "attack_type": attack_type,
        "ip": request.remote_addr,
        "method": request.method,
        "url": request.url,
        "details": details
    }
    
    log_file = os.path.join(LOG_DIR, f"attacks_{datetime.now().strftime('%Y%m%d')}.log")
    
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    print(f"[ATTACK DETECTED] {attack_type} from {request.remote_addr} - {details}")

# ============================================
# REVERSE PROXY ROUTES
# ============================================

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    """
    Main proxy function - inspects request and forwards if safe
    """
    # Inspect the request
    is_malicious, attack_type, details = inspect_request()
    
    if is_malicious:
        # Log the attack
        log_attack(attack_type, details)
        
        # Return blocked response
        return jsonify({
            "error": "Request blocked by WAF",
            "reason": attack_type,
            "message": "Your request has been identified as potentially malicious and has been blocked."
        }), 403
    
    # Request is safe - forward it to the backend
    try:
        # Build the target URL
        target_url = f"{BACKEND_URL}/{path}"
        
        # Forward the request
        if request.method == 'GET':
            resp = requests.get(target_url, params=request.args)
        elif request.method == 'POST':
            if request.is_json:
                resp = requests.post(target_url, json=request.get_json())
            else:
                resp = requests.post(target_url, data=request.form)
        elif request.method == 'PUT':
            resp = requests.put(target_url, json=request.get_json() if request.is_json else None)
        elif request.method == 'DELETE':
            resp = requests.delete(target_url)
        else:
            resp = requests.request(request.method, target_url)
        
        # Return the backend's response
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))
    
    except Exception as e:
        return jsonify({"error": "Backend error", "details": str(e)}), 500

# ============================================
# WAF DASHBOARD
# ============================================

@app.route('/waf/dashboard')
def dashboard():
    """Simple dashboard to view WAF status"""
    return """
    <html>
    <head>
        <title>WAF Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #2c3e50; }
            .info { background: #ecf0f1; padding: 20px; border-radius: 5px; }
            .status { color: green; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>🛡️ Web Application Firewall Dashboard</h1>
        <div class="info">
            <h2>Status: <span class="status">ACTIVE</span></h2>
            <p><strong>Protected Backend:</strong> http://127.0.0.1:5001</p>
            <p><strong>Detection Rules Active:</strong></p>
            <ul>
                <li>SQL Injection Detection</li>
                <li>Cross-Site Scripting (XSS) Detection</li>
                <li>Path Traversal Detection</li>
                <li>Command Injection Detection</li>
            </ul>
            <p><strong>Logs Location:</strong> ./logs/</p>
        </div>
        <h2>Test the WAF</h2>
        <p>Try these URLs to test attack detection:</p>
        <ul>
            <li><a href="/?test=<script>alert('xss')</script>">XSS Test</a></li>
            <li><a href="/search?q=' OR '1'='1">SQL Injection Test</a></li>
            <li><a href="/files?path=../../etc/passwd">Path Traversal Test</a></li>
        </ul>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("="*50)
    print("🛡️  WAF Starting...")
    print("="*50)
    print(f"WAF listening on: http://127.0.0.1:5000")
    print(f"Protected backend: {BACKEND_URL}")
    print(f"Logs directory: {LOG_DIR}")
    print("="*50)
    app.run(port=5000, debug=True)