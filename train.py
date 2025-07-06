import argparse
import json
import ipaddress
import gzip
from pathlib import Path

import joblib
import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import FeatureHasher
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler, FunctionTransformer
from sklearn.utils import Bunch

################################################################################
# --------------------------- Helper functions --------------------------------#
################################################################################

def is_internal(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip).is_private)
    except Exception:
        return 0

def load_alerts(log_dir: Path) -> pd.DataFrame:
    records = []
    for file in sorted(log_dir.glob("*.json*")):
        print(f"[+] Loading file: {file.name}")
        try:
            if file.suffix == ".gz":
                open_func = lambda f: gzip.open(f, mode="rt", encoding="utf-8", errors="ignore")
            else:
                open_func = lambda f: open(f, mode="r", encoding="utf-8", errors="ignore")

            with open_func(file) as fh:
                content = fh.read().strip()
                if content.startswith("["):
                    alerts = json.loads(content)
                    records.extend(flatten_alert(a) for a in alerts)
                else:
                    for line in content.splitlines():
                        if line.strip():
                            alert = json.loads(line)
                            records.append(flatten_alert(alert))
        except Exception as e:
            print(f"[!] Skipping {file.name} due to error: {e}")
    return pd.DataFrame(records)

MITRE_FIELDS = [
    ("mitre.tactic.name", "tactic"),
    ("mitre.technique.name", "technique"),
]

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

    for raw, col in MITRE_FIELDS:
        rec[f"mitre_{col}"] = get_nested(alert, raw, "none")

    srcip = get_nested(alert, "data.srcip", "0.0.0.0")
    dstip = get_nested(alert, "data.dstip", "0.0.0.0")
    rec["src_internal"] = is_internal(srcip)
    rec["dst_internal"] = is_internal(dstip)
    rec["src_port"] = int(get_nested(alert, "data.srcport", 0) or 0)
    rec["dst_port"] = int(get_nested(alert, "data.dstport", 0) or 0)
    rec["network_direction"] = get_nested(alert, "network.direction", "unknown")

    # ✅ Corrected extraction of process_path and file_path
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

    ts = get_nested(alert, "timestamp", None)
    if ts:
        ts = pd.to_datetime(ts, errors="coerce")
    rec["hour"] = ts.hour if ts is not pd.NaT else -1
    rec["weekday"] = ts.weekday() if ts is not pd.NaT else -1

    rec["ioc_hash_match"] = int(bool(get_nested(alert, "ioc_hash_match", False)))
    rec["blacklist_ip_score"] = float(get_nested(alert, "blacklist_ip_score", 0.0))

    # ✅ New feature: is file in temp folder?
    rec["is_temp_folder"] = int("temp" in ("/".join(rec["file_path"])).lower())

    # ✅ New feature: is process suspicious? (powershell, cmd, etc.)
    suspicious_keywords = ["powershell", "cmd", "wscript", "mshta"]
    rec["is_suspicious_process"] = int(any(x in ("/".join(rec["process_path"])).lower() for x in suspicious_keywords))

    rec["label"] = int(bool(get_nested(alert, "classifier.is_attack", False)))

    return rec

################################################################################
# --------------------------- Pre‑processing ----------------------------------#
################################################################################

NUMERIC_COLS = [
    "rule_level",
    "src_port",
    "dst_port",
    "blacklist_ip_score",
    "hour",
    "weekday",
    "is_temp_folder",          # ✅ Added
    "is_suspicious_process",   # ✅ Added
]

CATEGORICAL_ONEHOT = [
    "rule_groups",
    "mitre_tactic",
    "mitre_technique",
    "network_direction",
    "user_name",
    "logon_type",
    "event_id",
]

HASHED_TEXT = [
    "process_path",
    "file_path",
]

HASH_DIM = 256

def ensure_list(x):
    return x.apply(lambda lst: lst if isinstance(lst, list) else ["unknown"])

def build_preprocessor() -> ColumnTransformer:
    transformers = [
        ("num", StandardScaler(), NUMERIC_COLS),
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_ONEHOT),
    ]

    for col in HASHED_TEXT:
        transformers.append((
            f"hash_{col}",
            Pipeline(steps=[
                ("reshape", FunctionTransformer(ensure_list)),
                ("hasher", FeatureHasher(n_features=HASH_DIM, input_type="string"))
            ]),
            col
        ))

    return ColumnTransformer(transformers, remainder="drop")

def main(args):
    df = load_alerts(Path("logs"))
    if df.empty:
        raise SystemExit("[!] No alerts loaded – check input file.")

    y = df.pop("label")
    X = df

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=42
    )

    preproc = build_preprocessor()

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        n_jobs=-1,
        class_weight="balanced_subsample",
        random_state=42,
    )

    model = Pipeline(
        steps=[
            ("prep", preproc),
            ("rf", clf),
        ]
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n=== Evaluation report ===")
    print(classification_report(y_test, y_pred, digits=4))

    if args.model:
        joblib.dump(model, args.model)
        print(f"[+] Model saved to {args.model}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train RandomForest on Wazuh alerts")
    parser.add_argument("--model", default="model/rf_model.pkl", help="Output model filename")
    args = parser.parse_args()
    main(args)
