from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/')
def home():
    return """
    <h1>Vulnerable Web Application</h1>
    <p>This app is intentionally vulnerable for testing the WAF</p>
    <ul>
        <li><a href="/search?q=test">Search Page</a></li>
        <li><a href="/user?id=1">User Profile</a></li>
        <li><a href="/files?path=data.txt">File Access</a></li>
    </ul>
    """

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable to XSS - reflects user input without sanitization
    return f"<h2>Search Results for: {query}</h2>"

@app.route('/user')
def user():
    user_id = request.args.get('id', '')
    # Vulnerable to SQL injection (simulated)
    return f"<h2>User Profile</h2><p>Fetching user with ID: {user_id}</p>"

@app.route('/files')
def files():
    filepath = request.args.get('path', '')
    # Vulnerable to path traversal
    return f"<h2>File Access</h2><p>Accessing file: {filepath}</p>"

@app.route('/api/data', methods=['POST'])
def api_data():
    data = request.get_json()
    return jsonify({"received": data})

if __name__ == '__main__':
    app.run(port=5001, debug=True)