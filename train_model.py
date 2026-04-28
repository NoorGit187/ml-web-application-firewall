from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import joblib

# 📊 Sample training data
data = [
    # ✅ Safe inputs
    "hello world",
    "login page",
    "user input",
    "normal text",
    "search query",
    "good morning",

    # ❌ SQL Injection
    "SELECT * FROM users",
    "' OR 1=1 --",
    "UNION SELECT password",
    "DROP TABLE users",

    # ❌ XSS
    "<script>alert(1)</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert(1)>",

    # ❌ Command Injection
    "ls -la",
    "whoami",
    "cat /etc/passwd",
    "ping 127.0.0.1"
]

# Labels: 0 = safe, 1 = attack
labels = [
    0, 0, 0, 0, 0, 0,   # safe
    1, 1, 1, 1,         # SQL
    1, 1, 1,            # XSS
    1, 1, 1, 1          # Command
]

# 🔤 Convert text to numbers
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(data)

# 🤖 Train model
model = MultinomialNB()
model.fit(X, labels)

# 💾 Save model
joblib.dump(model, "waf_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("✅ Model trained and saved successfully!")