PhishGuard – Real-Time Phishing URL Detection Chrome Extension

PhishGuard is a Chrome extension that detects phishing websites in real-time using a machine learning model hosted on a Flask backend. It automatically scans the currently active tab’s URL, analyzes its features, and classifies it as Safe or Phishing.

-->Features
Automatically detects the URL of the active tab
Uses a trained Gradient Boosting Classifier to classify URLs
Predicts phishing threats in real-time
Chrome extension with Flask + Python backend
Clean and lightweight interface

-->Tech Stack
Frontend: HTML, CSS, JavaScript (Chrome Extension APIs)
Backend: Python, Flask, Scikit-learn, Joblib
Model: Gradient Boosting Classifier
Other Tools: VS Code, Git, Google Chrome

-->Load Chrome Extension
Go to chrome://extensions
Enable Developer Mode
Click Load unpacked
Select the phishing-extension/ folder
Open any website and click the extension icon

