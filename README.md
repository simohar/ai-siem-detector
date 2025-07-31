# 🧠🔐 AI-Powered SIEM with Wazuh Integration

## Overview

This project is an **AI-enhanced Security Information and Event Management (SIEM)** system built on top of **Wazuh**. It leverages machine learning to detect malicious behavior in real-time by analyzing and classifying enriched logs collected from endpoints (e.g., via Sysmon, Winlogbeat, Elastic Agent).

The goal is to assist SOC teams by improving detection accuracy, reducing false positives, and enabling smarter incident triage.

---

## 🔍 Features

- ✅ Real-time log ingestion via Wazuh
- ✅ Enriched logs using Wazuh rule engine (`rule.level`, `mitre.*`, etc.)
- ✅ Supervised ML classification (XGBoost, RandomForest, etc.)
- ✅ Support for log labeling using `classifier.is_attack`
- ✅ Feature engineering on security-relevant fields
- ✅ Option for real-time or batch inference
- ✅ Extendable architecture for large-scale deployments

---

## 🧰 Tech Stack

- **SIEM Core**: [Wazuh](https://wazuh.com/)
- **Log Sources**: Sysmon, Winlogbeat, Elastic Agent
- **ML Frameworks**: Python, Scikit-learn, XGBoost
- **Dashboards (optional)**: Streamlit or Kibana
- **Log Transport**: Wazuh API / Local files

---

## 📁 Folder Structure

ai-siem-wazuh/
├── fetch/ # Log ingestion & retrieval
├── preprocess/ # Feature engineering & cleaning
├── train/ # Model training scripts
├── evaluate/ # Metrics & validation
├── inference/ # Inference pipeline
├── models/ # Saved model files
├── config/ # Configuration files
├── notebooks/ # Exploratory analysis
├── requirements.txt
└── README.md



---

## ⚙️ How It Works

1. **Collection**  
   Wazuh agents collect and forward logs to the Wazuh manager.

2. **Enrichment**  
   Wazuh tags logs with `rule.level`, MITRE tags, process path, etc.

3. **Labeling**  
   Logs are labeled using `classifier.is_attack` or other custom logic.

4. **Training**  
   Machine learning models are trained on enriched & labeled logs.

5. **Inference**  
   New logs are classified in real-time or batch mode to detect threats.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Wazuh (Manager + Agents)
- Access to Wazuh REST API
- Enriched and labeled dataset (or collection configured)

### Installation

git clone https://github.com/yourusername/ai-siem-detector.git
cd ai-siem-detector
pip install -r requirements.txt

---

## ⚙️ How It Works

1. **Collection**  
   Wazuh agents collect and forward logs to the Wazuh manager.

2. **Enrichment**  
   Wazuh tags logs with `rule.level`, MITRE tags, process path, etc.

3. **Labeling**  
   Logs are labeled using `classifier.is_attack` or other custom logic.

4. **Training**  
   Machine learning models are trained on enriched & labeled logs.

5. **Inference**  
   New logs are classified in real-time or batch mode to detect threats.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Wazuh (Manager + Agents)
- Access to Wazuh REST API
- Enriched and labeled dataset (or collection configured)

### Installation

```bash
git clone https://github.com/yourusername/ai-siem-wazuh.git
cd ai-siem-wazuh
pip install -r requirements.txt

## Modell Training

cd train
python train_model.py

## Evaluation

Accuracy

Precision / Recall

F1-score

ROC-AUC

Confusion Matrix


## Future work

Add zero-day anomaly detection via unsupervised models

Build feedback loop from analyst verdicts

Automate labeling pipeline for raw Sysmon logs

Integration with SOAR tools

## Contribution

Contributions are welcome! Please open an issue or submit a pull request.
Ensure your changes are well-documented and tested.

## Licence
MIT License

## Contact
Created by Mohamed Harrata
Feel free to connect on LinkedIn or reach out via email.
