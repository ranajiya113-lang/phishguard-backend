 PhishGuard — Machine Learning Based Phishing Detection
> **PhishGuard** is a phishing URL detection system developed using FastAPI and Machine Learning. It analyzes URLs using feature extraction and classification techniques to identify potentially malicious websites.

 Overview

PhishGuard is designed to help identify phishing URL by analyzing different characteristics of a URL. The backend extracts multiple URL-based features and passes them to a trained machine learning model, which predicts whether the URL is legitimate or phishing.

The project demonstrates the practical use of Machine Learning in cybersecurity while following a modular backend architecture.



 1. Features

*  URL Phishing Detection
*  Machine Learning-Based Prediction
*  FastAPI REST API
*  URL Feature Extraction
*  JSON Response Format
*  Interactive Swagger Documentation
*  Render Deployment Support
*  Modular Backend Structure

---

2. Project Structure

text
phishguard-backend/
│
├── app/
│   ├── main.py
│   ├── detector.py
│   └── __init__.py
│
├── models/
│   ├── phishing_model.pkl
│   └── phishing_model_v2.pkl
│
├── utils/
│   ├── heuristics.py
│   ├── ml_model.py
│   ├── threat_intel.py
│   ├── url_utils.py
│   └── __init__.py
│
├── requirements.txt
├── render.yaml
└── README.md


 3.Tech Stack

 Backend

* Python 3.11
* Fast API
* Scikit-learn
* NumPy
* HTTPX
* Uvicorn

4. Workflow

1. User submits a URL.
2. The backend validates the input.
3. URL features are extracted.
4. The trained machine learning model processes those features.
5. The prediction is returned as a JSON response.

 5.Sample Response


{
  "prediction": "Phishing",
  "confidence": 0.94
}


6. 🎯 Future Improvements

* Improve model performance with additional training data.
* Add support for domain reputation services.
* Implement Docker support.
* Add automated testing.
* Introduce CI/CD for deployment.
* Enhance API logging and monitoring.

---

 Developer

**Jiya Rana**

Cybersecurity & Machine Learning Enthusiast

GitHub: https://github.com/ranajiya113-lang/phishguard-backend

---


