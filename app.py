from flask import Flask, request, render_template_string
import re
from datetime import datetime
import joblib

app = Flask(__name__)

# 🔒 Progressive Blocking
blocked_ips = {}
BLOCK_LEVELS = [60, 300, 900]  # 1 min, 5 min, 15 min

# 📊 Rate Limiting
request_counts = {}
RATE_LIMIT = 7   # increased to avoid false block
TIME_WINDOW = 11

# 🤖 Load ML model
model = joblib.load("waf_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# 🔍 Patterns (PRIMARY detection)
sql_patterns = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"\b(SELECT|UNION|INSERT|UPDATE|DELETE)\b",
    r"\bOR\b.+="
]

xss_patterns = [
    r"<script.*?>.*?</script>",
    r"javascript:",
    r"on\w+\s*="
]

cmd_patterns = [
    r";", r"&&", r"\|\|", r"\$", r"`",
    r"\b(cat|ls|pwd|whoami|ping)\b"
]

# 📝 Logging
def log_attack(ip, payload, attempts):
    with open("waf_logs.txt", "a") as f:
        f.write(f"{datetime.now()} | {ip} | ATTEMPTS: {attempts} | BLOCKED | {payload}\n")

# 🧠 Detection (SAFE VERSION)
def is_malicious(payload):
    # 🔍 Step 1: Regex (trusted)
    for pattern in sql_patterns + xss_patterns + cmd_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True

    # 🤖 Step 2: ML (only for long suspicious input)
    if len(payload) > 8:
        X = vectorizer.transform([payload])
        prediction = model.predict(X)[0]

        if prediction == 1:
            return True

    return False

# 🔥 WAF Middleware
@app.before_request
def waf():
    ip = request.remote_addr
    current_time = datetime.now().timestamp()

    # 📊 RATE LIMIT
    if ip not in request_counts:
        request_counts[ip] = []

    request_counts[ip] = [
        t for t in request_counts[ip]
        if current_time - t < TIME_WINDOW
    ]

    request_counts[ip].append(current_time)

    if len(request_counts[ip]) > RATE_LIMIT:
        return render_template_string("""
            <h1 style="color:red;">🚫 Too Many Requests</h1>
            <p>You are sending too many requests.</p>
        """), 429

    # 🔁 PROGRESSIVE BLOCK
    if ip in blocked_ips:
        block_start, attempts = blocked_ips[ip]
        block_duration = BLOCK_LEVELS[min(attempts - 1, len(BLOCK_LEVELS) - 1)]

        if current_time - block_start < block_duration:
            return render_template_string(f"""
                <h1 style="color:red;">🚫 Access Denied</h1>
                <p>Blocked due to repeated attacks.</p>
                <p>Attempts: {attempts}</p>
            """), 403
        else:
            del blocked_ips[ip]

    # 🔍 CHECK INPUT
    for value in list(request.args.values()) + list(request.form.values()):
        if is_malicious(value):
            attempts = blocked_ips.get(ip, (0, 0))[1] + 1
            blocked_ips[ip] = (current_time, attempts)
            log_attack(ip, value, attempts)

            return render_template_string(f"""
                <h1 style="color:red;">🚫 Request Blocked</h1>
                <p>Malicious input detected.</p>
                <p>Attempts: {attempts}</p>
            """), 403

# 🌐 HOME
@app.route('/')
def home():
    return render_template_string("""
        <h1>🛡 AI-Based Web Application Firewall</h1>
        <p>Test your input:</p>
        <form action="/submit" method="POST">
            <input type="text" name="input" required>
            <input type="submit">
        </form>
    """)

# 📩 SUBMIT
@app.route('/submit', methods=['POST'])
def submit():
    data = request.form.get('input')
    return f"""
        <h2 style='color:green;'>✅ Safe Input</h2>
        <p>You entered: {data}</p>
        <a href="/">Go Back</a>
    """

# 🚀 RUN
if __name__ == '__main__':
    app.run(debug=True)