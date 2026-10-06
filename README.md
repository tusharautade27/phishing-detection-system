# AI-Based Phishing Detection System

A machine learning web application that detects phishing websites 
in real-time using Random Forest classification.

## 🎯 Accuracy
- **89% detection accuracy** on 549,000 real-world URLs
- Dataset sourced from PhishTank (real phishing URLs)
- 30 engineered URL-based features

## 🛠️ Tech Stack
- **Backend:** Python, Flask
- **ML Model:** Random Forest (scikit-learn)
- **Database:** MySQL
- **APIs:** Google Safe Browsing API
- **Tools:** Git, VS Code

## ✨ Features
- Real-time URL phishing detection
- 30 URL feature extraction including:
  - Domain entropy analysis
  - Brand spoofing detection
  - Suspicious TLD checking
  - IP address detection
  - URL pattern analysis
- Risk scoring with confidence analysis
- Google Safe Browsing API integration

## 📊 Model Performance
| Metric | Score |
|--------|-------|
| Accuracy | 89.01% |
| Precision (phishing) | 80% |
| Recall (phishing) | 81% |
| Training samples | 549,000 URLs |

## 🚀 How to Run
```bash
# Clone the repo
git clone https://github.com/tusharautade27/phishing-detection-system

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```


