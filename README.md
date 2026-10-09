<h1 align="center">PhishGuard-ML: Phishing URL Detection System</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Flask-Web%20Framework-lightgrey.svg" alt="Flask Framework">
  <img src="https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-orange.svg" alt="Machine Learning">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
</p>

<p align="center">
  A Machine Learning-based Phishing URL Detection web application built with Flask and Scikit-Learn.
</p>

---

## 📖 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Usage](#-usage)
- [Model Training](#-model-training)

## 🔍 Overview
**PhishGuard-ML** uses a trained **Gradient Boosting Classifier** to detect malicious and phishing URLs. By extracting 30 specific lexical and network-based features from a given URL, the model determines whether the URL is safe or potentially dangerous. 

## ✨ Features
- **User Authentication**: Secure login and registration powered by SQLite.
- **Real-Time URL Analysis**: Extracts 30 features from the input URL on-the-fly.
- **High Accuracy ML Model**: Uses a Gradient Boosting algorithm trained on comprehensive phishing datasets.
- **Interactive UI**: A clean, responsive user interface to interact with the application.

## 📂 Project Structure
```text
PhishGuard-ML/
│
├── app.py                   # Main Flask application entry point
├── feature.py               # Feature extraction logic for URLs
├── retrain.py               # Script to train/retrain the ML model
├── requirements.txt         # Project dependencies
├── README.md                # Project documentation
│
├── data/                    # Datasets used for training
│   ├── dataset.csv
│   └── phishing.csv
│
├── models/                  # Serialized ML models
│   └── model.pkl
│
├── notebooks/               # Jupyter notebooks for data exploration
│   └── Phishing URL Detection.ipynb
│
├── docs/                    # Project images and documentation assets
│   ├── IMG1.png
│   ├── IMG2.png
│   └── IMG3.png
│
├── static/                  # CSS, JS, and image assets for the web app
└── templates/               # HTML templates for the Flask app
```

## ⚙️ Prerequisites
Ensure you have the following installed:
- [Python 3.8+](https://www.python.org/downloads/)
- [Git](https://git-scm.com/) (optional, for cloning the repository)

## 🚀 Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Darshan-2006/PhishGuard-ML.git
   cd PhishGuard-ML
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**:
   - **Windows**:
     ```bash
     venv\Scripts\activate
     ```
   - **macOS/Linux**:
     ```bash
     source venv/bin/activate
     ```

4. **Install required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

1. **Start the Flask server**:
   ```bash
   python app.py
   ```

2. **Access the web application**:
   Open your web browser and navigate to:
   [http://127.0.0.1:5000](http://127.0.0.1:5000)

3. **Interact**: Register a new user, log in, and enter any URL to check if it's safe or a phishing attempt!

## 🧠 Model Training

If you encounter compatibility issues with the pre-trained model (e.g., `ModuleNotFoundError` or pickle-related errors due to different scikit-learn versions), you can easily retrain the model locally.

Run the retraining script:
```bash
python retrain.py
```
*This script will train a new Gradient Boosting Classifier on `data/dataset.csv` and automatically save the updated model to `models/model.pkl`.*

---
<p align="center">
  Developed by <a href="https://github.com/Darshan-2006">Darshan-2006</a>
</p>
