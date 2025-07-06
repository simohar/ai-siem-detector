import json
import gzip
import pandas as pd
from pathlib import Path

def load_wazuh_logs(file_path):
    logs = []
    if file_path.suffix == '.gz':
        open_fn = gzip.open
    else:
        open_fn = open

    with open_fn(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
        for line in f:
            try:
                log = json.loads(line)
                logs.append(log)
            except json.JSONDecodeError:
                continue
    return logs

def parse_log_entry(entry):
    try:
        return {
            'timestamp': entry.get('timestamp'),
            'rule_level': entry.get('rule', {}).get('level'),
            'rule_description': entry.get('rule', {}).get('description'),
            'rule_groups': entry.get('rule', {}).get('groups'),
            'event_id': entry.get('data', {}).get('win', {}).get('system', {}).get('eventID'),
            'logon_type': entry.get('data', {}).get('win', {}).get('eventdata', {}).get('logonType'),
            'process_name': entry.get('data', {}).get('win', {}).get('eventdata', {}).get('processName'),
            'target_user': entry.get('data', {}).get('win', {}).get('eventdata', {}).get('targetUserName'),
            'elevated_token': entry.get('data', {}).get('win', {}).get('eventdata', {}).get('elevatedToken'),
            'status': entry.get('data', {}).get('status'),
            'full_log': entry.get('full_log'),
            'source_ip': entry.get('agent', {}).get('ip')
        }
    except Exception:
        return None

def label_log(row):
    rule_level = row.get('rule_level') or 0
    description = (row.get('rule_description') or '').upper()
    status = (row.get('status') or '').upper()
    full_log = (row.get('full_log') or '').upper()
    rule_groups = row.get('rule_groups') or []

    risk_score = rule_level

    if "DENIED" in description or "DENIED" in full_log:
        risk_score += 2
    if status == "DENIED":
        risk_score += 2
    if any("AUTHENTICATION" in g.upper() or "FAILED" in g.upper() for g in rule_groups):
        risk_score += 1
    if "FAILED" in description or "FAIL" in full_log:
        risk_score += 1

    return 1 if risk_score >= 7 else 0

def main(folder_path):
    folder = Path(folder_path)
    all_logs = []

    print(f"🔎 Lecture des fichiers dans le dossier : {folder.resolve()}")

    for file in folder.glob("*.json*"):
        print(f"📄 Traitement : {file.name}")
        logs = load_wazuh_logs(file)
        parsed_logs = [parse_log_entry(log) for log in logs]
        parsed_logs = [log for log in parsed_logs if log is not None]
        all_logs.extend(parsed_logs)

    if not all_logs:
        print("❌ Aucun log valide trouvé.")
        return

    df = pd.DataFrame(all_logs)
    df['label'] = df.apply(label_log, axis=1)

    print(f"✅ {len(df)} logs au total après fusion et labellisation.")
    df.to_csv('logs_to_predict.csv', index=False)
    print("💾 Fichier final sauvegardé :logs_to_predict.csv")

if __name__ == "__main__":
    main("logs")  # nom du dossier contenant les .json ou .json.gz
