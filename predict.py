import json
import gzip
from pathlib import Path
import pandas as pd
import joblib
from utils import ensure_list, is_internal
from datetime import datetime

def get_nested(obj: dict, dotted: str, default=None):
    cur = obj
    for k in dotted.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur

def flatten_alert(alert: dict) -> dict:
    rec = {}
    rec["rule_level"] = get_nested(alert, "rule.level", 0)
    rec["rule_id"] = get_nested(alert, "rule.id", "unknown")
    rec["rule_groups"] = ",".join(get_nested(alert, "rule.groups", []))

    rec["mitre_tactic"] = get_nested(alert, "mitre.tactic.name", "none")
    rec["mitre_technique"] = get_nested(alert, "mitre.technique.name", "none")

    srcip = get_nested(alert, "data.srcip", "0.0.0.0")
    dstip = get_nested(alert, "data.dstip", "0.0.0.0")
    rec["src_internal"] = is_internal(srcip)
    rec["dst_internal"] = is_internal(dstip)
    rec["src_port"] = int(get_nested(alert, "data.srcport", 0) or 0)
    rec["dst_port"] = int(get_nested(alert, "data.dstport", 0) or 0)
    rec["network_direction"] = get_nested(alert, "network.direction", "unknown")

    # ✅ Corriger l'extraction des chemins
    process_path = (
        get_nested(alert, "process.path", "") or
        get_nested(alert, "data.win.eventdata.image", "") or
        get_nested(alert, "data.win.system.image", "")
    )

    file_path = (
        get_nested(alert, "file.path", "") or
        get_nested(alert, "data.win.eventdata.targetFilename", "") or
        get_nested(alert, "data.win.system.targetFilename", "")
    )

    rec["process_path"] = (
        process_path.lower().replace("\\", "/").split("/") if isinstance(process_path, str) and process_path else ["unknown"]
    )

    rec["file_path"] = (
        file_path.lower().replace("\\", "/").split("/") if isinstance(file_path, str) and file_path else ["unknown"]
    )

    rec["user_name"] = get_nested(alert, "user.name", "none")
    rec["logon_type"] = get_nested(alert, "logon.type", "none")
    rec["event_id"] = str(get_nested(alert, "winlog.event_id", "0"))

    # ✅ Extraire heure et jour
    ts = get_nested(alert, "timestamp", None)
    if ts:
        ts = pd.to_datetime(ts, errors="coerce")
    rec["hour"] = ts.hour if ts is not pd.NaT else -1
    rec["weekday"] = ts.weekday() if ts is not pd.NaT else -1

    rec["ioc_hash_match"] = int(bool(get_nested(alert, "ioc_hash_match", False)))
    rec["blacklist_ip_score"] = float(get_nested(alert, "blacklist_ip_score", 0.0))

    # ✅ Nouvelle feature : fichier dans Temp ?
    rec["is_temp_folder"] = int("temp" in ("/".join(rec["file_path"])).lower())

    # ✅ Nouvelle feature : processus suspect ?
    suspicious_keywords = ["powershell", "cmd", "wscript", "mshta"]
    rec["is_suspicious_process"] = int(any(x in ("/".join(rec["process_path"])).lower() for x in suspicious_keywords))

    # Même si on ne l’utilise pas dans la prédiction
    rec["label"] = int(bool(get_nested(alert, "classifier.is_attack", False)))

    return rec

def load_alerts_for_prediction(log_dir: Path) -> pd.DataFrame:
    records = []
    for file in sorted(log_dir.glob("*.json*")):
        print(f"[+] Loading file: {file.name}")
        try:
            if file.suffix == ".gz":
                open_func = lambda f: gzip.open(f, mode="rt", encoding="utf-8", errors="ignore")
            else:
                open_func = lambda f: open(f, mode="r", encoding="utf-8", errors="ignore")

            with open_func(file) as fh:
                try:
                    content = fh.read().strip()
                    if content.startswith("["):
                        alerts = json.loads(content)
                        records.extend(flatten_alert(a) for a in alerts)
                    else:
                        try:
                            alert = json.loads(content)
                            records.append(flatten_alert(alert))
                        except json.JSONDecodeError:
                            for line in content.splitlines():
                                if line.strip():
                                    alert = json.loads(line)
                                    records.append(flatten_alert(alert))
                except json.JSONDecodeError as e:
                    print(f"[!] Skipping {file.name} due to JSON error: {e}")

        except Exception as e:
            print(f"[!] Skipping {file.name} due to error: {e}")
    return pd.DataFrame(records)

def main():
    model_path = Path("model/rf_model.pkl")
    logs_dir = Path("test")
    output_file = Path("predictions.csv")

    print(f"[+] Loading model from {model_path}")
    model = joblib.load(model_path)

    df = load_alerts_for_prediction(logs_dir)
    if df.empty:
        print(f"[!] No alerts loaded from {logs_dir}. Please check the directory and file formats.")
        return

    X = df.drop(columns=["label"], errors="ignore")

    predictions = model.predict(X)

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        if proba.shape[1] == 1:
            df["attack_proba"] = 0.0
        else:
            df["attack_proba"] = proba[:, 1]
    else:
        df["attack_proba"] = 0.0

    df["prediction"] = predictions

    print("\n=== Predictions Summary ===")
    print(df["prediction"].value_counts())

    df.to_csv(output_file, index=False)
    print(f"[+] Predictions saved to {output_file}")

if __name__ == "__main__":
    main()
