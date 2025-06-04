import pandas as pd
import numpy as np
import joblib
import sys
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

MODEL_PATH = "model/rf_model.pkl"
FEATURES = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Bwd Pkt Len Max",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Pkt Len Var",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt"
]
CHUNK_SIZE = 50000

def simplify_prediction(pred):
    return "BENIGN" if pred == 1 else "ATTACK"

def simplify_label(label):
    return "BENIGN" if "BENIGN" in str(label).upper() else "ATTACK"

def process_chunk(chunk, model):
    chunk.columns = chunk.columns.str.strip()
    chunk_original = chunk.copy()

    try:
        chunk = chunk[FEATURES].copy()
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(inplace=True)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(chunk)
        preds = model.predict(X_scaled).ravel()

        chunk_result = chunk_original.loc[chunk.index].copy()
        chunk_result["Prediction"] = [simplify_prediction(p) for p in preds]
        return chunk_result
    except Exception as e:
        raise ValueError(f"Erreur dans le traitement du chunk : {e}")

def main():
    if len(sys.argv) < 2:
        print("🔴 Usage : python confusion_matrix.py chemin/vers/fichier.csv")
        return

    file_path = sys.argv[1]
    model = joblib.load(MODEL_PATH)

    print(f"📥 Lecture par chunks de : {file_path}")
    all_results = []

    for i, chunk in enumerate(pd.read_csv(file_path, chunksize=CHUNK_SIZE)):
        try:
            chunk_result = process_chunk(chunk, model)
            all_results.append(chunk_result)
            print(f"✅ Chunk {i+1} traité avec succès. ({len(chunk_result)} lignes valides)")
        except Exception as e:
            print(f"⚠️ Erreur dans le chunk {i+1} : {e}")

    df_final = pd.concat(all_results, ignore_index=True)

    if "Label" not in df_final.columns:
        print("❌ Le fichier ne contient pas de colonne 'Label'. Impossible d’évaluer.")
        return

    df_final["Label"] = df_final["Label"].apply(simplify_label)

    y_true = df_final["Label"]
    y_pred = df_final["Prediction"]

    # 📊 Rapport texte
    print("\n📈 Rapport de classification :\n")
    print(classification_report(y_true, y_pred))

    # 📉 Diagramme de confusion
    cm = confusion_matrix(y_true, y_pred, labels=["ATTACK", "BENIGN"])
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["ATTACK", "BENIGN"], yticklabels=["ATTACK", "BENIGN"])
    plt.title("Matrice de confusion")
    plt.xlabel("Prédiction")
    plt.ylabel("Vrai label")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()
