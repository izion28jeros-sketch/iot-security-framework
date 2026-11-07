"""Intrusion detection module (Module 4).
Trains a gradient-boosted tree classifier on labelled flows, evaluates it on a
held-out 30% test split, measures inference time, and writes the metrics and the
alerts for attack flows in the test split into the database.
Uses XGBoost when installed; otherwise scikit-learn's HistGradientBoostingClassifier
(the same gradient boosting family)."""
import json, sqlite3, sys, time, datetime, os
import numpy as np, pandas as pd, joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
csv, db = sys.argv[1], sys.argv[2]
df = pd.read_csv(csv)
X, y = df.drop(columns=["label"]), df["label"]
classes = ["normal", "dos", "mitm"]; yi = y.map({c: i for i, c in enumerate(classes)})
Xtr, Xte, ytr, yte = train_test_split(X, yi, test_size=0.30, stratify=yi, random_state=42)
try:
    from xgboost import XGBClassifier
    model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, eval_metric="mlogloss"); name = "XGBoost"
except ImportError:
    from sklearn.ensemble import HistGradientBoostingClassifier
    model = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, random_state=42); name = "Gradient boosting (scikit-learn HistGradientBoosting)"
model.fit(Xtr, ytr)
t0 = time.perf_counter(); pred = model.predict(Xte); dt = time.perf_counter() - t0
latency = 1000 * dt / len(Xte) * 1000          # ms per 1000 flows
acc = accuracy_score(yte, pred)
cm = confusion_matrix(yte, pred, labels=[0, 1, 2])
neg = (yte == 0); fpr = float(((pred != 0) & neg).sum() / neg.sum())
binary_acc = float(((pred != 0) == (yte != 0)).mean())
rep = classification_report(yte, pred, labels=[0, 1, 2], target_names=classes, output_dict=True, digits=4)
per_class = {c: {k: round(rep[c][k], 4) for k in ("precision", "recall", "f1-score", "support")} for c in classes}
per_class["_binary_accuracy"] = round(binary_acc, 4); per_class["_confusion"] = cm.tolist()
os.makedirs(os.path.dirname(os.path.abspath(__file__)) + "/../data", exist_ok=True)
joblib.dump(model, os.path.dirname(os.path.abspath(__file__)) + "/../data/ids_model.joblib")
con = sqlite3.connect(db); cur = con.cursor()
cur.execute("INSERT INTO ids_runs (model, dataset, n_train, n_test, accuracy, fpr, latency_ms_per_1000, per_class_json) VALUES (?,?,?,?,?,?,?,?)",
            (name, f"{os.path.basename(csv)}: synthetic smart home flows ({len(df)} flows)", len(Xtr), len(Xte), round(acc, 4), round(fpr, 4), round(latency, 2), json.dumps(per_class)))
# alerts: attack predictions on the latest 400 test flows, replayed as a monitoring window
proba = model.predict_proba(Xte.iloc[-400:])
now = datetime.datetime.now().replace(microsecond=0)
devs = ["127.0.10.11", "127.0.10.12", "127.0.10.13", "127.0.10.14", "127.0.10.15"]
for i, (p, pr) in enumerate(zip(pred[-400:], proba)):
    if p != 0:
        t = now - datetime.timedelta(seconds=3 * (400 - i))
        cur.execute("INSERT INTO ids_alerts (alert_time, source_ip, dest_ip, attack_type, confidence) VALUES (?,?,?,?,?)",
                    (t.strftime("%Y-%m-%d %H:%M:%S"), "127.0.10.99", devs[i % 5], classes[p].upper(), round(float(pr.max()), 4)))
con.commit()
print(json.dumps({"model": name, "accuracy": round(acc, 4), "binary_accuracy": round(binary_acc, 4), "fpr": round(fpr, 4),
                  "latency_ms_per_1000": round(latency, 2), "n_train": len(Xtr), "n_test": len(Xte), "per_class": per_class}, indent=1))
