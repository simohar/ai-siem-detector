import os
import glob
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# 📂 Paramètres
DATA_DIR = "data"
CHUNK_SIZE = 20000
MODEL_PATH = "model/rf_model.pkl"

features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Variance",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count"
]

def simplify_label(label):
    label = label.lower()
    return "BENIGN" if "benign" in label else "ATTACK"

def process_chunk(chunk): 
    chunk.columns = chunk.columns.str.strip()  # Élimine les espaces
    expected_cols = features + ["Label"]
    missing = [col for col in expected_cols if col not in chunk.columns]
    if missing:
        raise ValueError(f"❌ Colonnes manquantes : {missing}")
    
    chunk = chunk[expected_cols].dropna()
    chunk["Label"] = chunk["Label"].apply(simplify_label)
    return chunk


# 📊 Agrégation des données en chunks
data_list = []
for file in glob.glob(os.path.join(DATA_DIR, "*.csv")):
    print(f"🔹 Lecture de : {file}")
    try:
        for chunk in pd.read_csv(file, chunksize=CHUNK_SIZE):
            processed = process_chunk(chunk)
            data_list.append(processed)
    except Exception as e:
        print(f"⚠️ Erreur avec {file} : {e}")

# 🧹 Fusion & préparation
df = pd.concat(data_list, ignore_index=True)
X = df[features]
y = df["Label"]

X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.dropna(inplace=True)
y = y[X.index]

# 🔄 Encodage et normalisation
le = LabelEncoder()
y_encoded = le.fit_transform(y)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 🔀 Split des données
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_encoded, test_size=0.2, random_state=42)

# 🌳 Entraînement du modèle
print("🎯 Entraînement du modèle RandomForest...")
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# 🧪 Évaluation
y_pred = clf.predict(X_test)
print("\n📈 Rapport de classification :\n")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# 💾 Sauvegarde
joblib.dump(clf, MODEL_PATH)
print(f"\n✅ Modèle sauvegardé : {MODEL_PATH}")
