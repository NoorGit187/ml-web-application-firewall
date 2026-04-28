# 🛡️ ML-Based Web Application Firewall (WAF)

This project is a Machine Learning-based Web Application Firewall built using Flask.
It detects and blocks common web attacks like SQL Injection, Cross-Site Scripting (XSS), and Command Injection.

---

## 🚀 Features

* SQL Injection Detection
* XSS (Cross-Site Scripting) Protection
* Command Injection Detection
* Machine Learning-based input classification
* Progressive IP Blocking
* Rate Limiting (to prevent excessive requests)
* Logging of malicious activity

---

## 🧠 How It Works

* User input is first checked using **regex patterns** for known attacks
* Then it is passed to a **machine learning model** for classification
* If the input is malicious:

  * The request is blocked
  * The IP can be temporarily blocked
  * The activity is logged
* If the input is safe:

  * The request is allowed

---

## 🛠️ Technologies Used

* Python
* Flask
* Scikit-learn
* Joblib

---

## ▶️ How to Run

1. Install dependencies:

   ```
   pip install flask scikit-learn joblib
   ```

2. Train the model:

   ```
   python train_model.py
   ```

3. Run the application:

   ```
   python app.py
   ```

4. Open in browser:

   ```
   http://127.0.0.1:5000
   ```

---

## 🧪 Sample Inputs for Testing

* `' OR 1=1 --` → SQL Injection
* `<script>alert(1)</script>` → XSS
* `whoami` → Command Injection

---

## 📄 Logs

All blocked requests are recorded in:

```
waf_logs.txt
```

---

## ⚠️ Note

This is a **basic prototype project** created for learning purposes.
It demonstrates how a WAF can be built using both rule-based and machine learning approaches.

---

## 👨‍💻 Author

Noor Ahmed
