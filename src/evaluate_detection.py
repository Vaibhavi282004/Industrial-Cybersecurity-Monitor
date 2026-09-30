import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)

INPUT_FILE = "data/ot_network_logs.csv"
DETECTED_FILE = "data/detected_security_events.csv"

# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------

original = pd.read_csv(INPUT_FILE)
detected = pd.read_csv(DETECTED_FILE)

# --------------------------------------------------
# CREATE BINARY GROUND TRUTH
# --------------------------------------------------

ATTACK_TYPES = {
    "PORT_SCAN",
    "EXCESSIVE_MODBUS",
    "FAILED_ACCESS",
    "UNAUTHORIZED_OT"
}

original["actual_attack"] = (
    original["event_type"].isin(ATTACK_TYPES)
)

# --------------------------------------------------
# CREATE BINARY PREDICTION
# --------------------------------------------------

detected_indexes = set(detected.index)

original["predicted_attack"] = (
    original.index.isin(detected_indexes)
)

# --------------------------------------------------
# METRICS
# --------------------------------------------------

accuracy = accuracy_score(
    original["actual_attack"],
    original["predicted_attack"]
)

print("=" * 60)
print("OT SENTINEL - DETECTION EVALUATION")
print("=" * 60)

print("\nTotal Events:", len(original))

print(
    "Actual Attacks:",
    original["actual_attack"].sum()
)

print(
    "Detected Attacks:",
    original["predicted_attack"].sum()
)

print(
    "Accuracy:",
    round(accuracy, 4)
)

# --------------------------------------------------
# CLASSIFICATION REPORT
# --------------------------------------------------

print("\nClassification Report:")

print(
    classification_report(
        original["actual_attack"],
        original["predicted_attack"],
        target_names=[
            "NORMAL",
            "ATTACK"
        ],
        zero_division=0
    )
)

# --------------------------------------------------
# CONFUSION MATRIX
# --------------------------------------------------

cm = confusion_matrix(
    original["actual_attack"],
    original["predicted_attack"]
)

print("\nConfusion Matrix:")

print(cm)

# --------------------------------------------------
# ATTACK TYPE DISTRIBUTION
# --------------------------------------------------

print("\nActual Attack Distribution:")

print(
    original[
        original["actual_attack"]
    ]["event_type"].value_counts()
)

print("\nEvaluation completed.")