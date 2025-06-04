import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
import sys

# 🔧 Config
MODEL_PATH = "model/rf_model.pkl"
FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Bwd Packet Length Max",
    "Flow Bytes/s", "Flow Packets/s", "Packet Length Variance",
    "Fwd PSH Flags", "Fwd URG Flags", "FIN Flag Count", "SYN Flag Count", "RST Flag Count"
]

def load_model():
    return joblib.load(MODEL_PATH)

def preprocess_data(file_path):
    df = pd.read_csv(file_path)
    df.columns = df.columns.str.strip()
    if not all(col in df.columns for col in FEATURES):
        missing = [col for col in FEATURES if col not in df.columns]
        raise ValueError(f"Colonnes manquantes : {missing}")
    X = df[FEATURES].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.dropna(inplace=True)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)  # ⚠️ Utilise fit ici car pas de scaler sauvegardé
    return X_scaled, df

def main():
    if len(sys.argv) < 2:
        print("🔴 Usage : python inference.py chemin/vers/fichier.csv")
        return
    
    file_path = sys.argv[1]
    print(f"📥 Fichier d'entrée : {file_path}")
    model = load_model()
    X_scaled, df_original = preprocess_data(file_path)
    predictions = model.predict(X_scaled)
    
    df_original["Prediction"] = ["BENIGN" if p == 1 else "ATTACK" for p in predictions]
    print(df_original[["Prediction"]].value_counts())
    df_original.to_csv("inference_results.csv", index=False)
    print("✅ Résultat sauvegardé dans 'inference_results.csv'")

if __name__ == "__main__":
    main()
