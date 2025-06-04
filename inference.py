import pandas as pd
import numpy as np
import joblib
import sys
from sklearn.preprocessing import StandardScaler

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

def process_chunk(chunk, model):
    chunk.columns = chunk.columns.str.strip()
    
    # Copie originale pour synchroniser les index
    chunk_original = chunk.copy()

    try:
        chunk = chunk[FEATURES].copy()
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(inplace=True)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(chunk)
        preds = model.predict(X_scaled).ravel()

        chunk_result = chunk_original.loc[chunk.index]
        chunk_result["Prediction"] = ["BENIGN" if p == 1 else "ATTACK" for p in preds]
        return chunk_result
    except Exception as e:
        raise ValueError(f"Erreur dans le traitement du chunk : {e}")


def main():
    if len(sys.argv) < 2:
        print("🔴 Usage : python inference.py chemin/vers/fichier.csv")
        return

    file_path = sys.argv[1]
    model = joblib.load(MODEL_PATH)

    print(f"📥 Lecture par chunks de : {file_path}")
    output_file = "inference_results.csv"
    writer = open(output_file, "w")
    header_written = False

    all_preds = []  

    for i, chunk in enumerate(pd.read_csv(file_path, chunksize=CHUNK_SIZE)):
        try:
            chunk_result = process_chunk(chunk, model)
            all_preds.extend(chunk_result["Prediction"])

            if not header_written:
                chunk_result.to_csv(writer, index=False)
                header_written = True
            else:
                chunk_result.to_csv(writer, index=False, header=False)

            print(f"✅ Chunk {i+1} traité avec succès. ({len(chunk_result)} lignes valides)")
        except Exception as e:
            print(f"⚠️ Erreur dans le chunk {i+1} : {e}")

    writer.close()
    print(f"\n📦 Résultats écrits dans : {output_file}")

    print("\n📊 Résumé des prédictions :")
    summary = pd.Series(all_preds).value_counts()
    for label in ["ATTACK", "BENIGN"]:
        count = summary.get(label, 0)
        print(f" - {label} : {count} lignes")

if __name__ == "__main__":
    main()
