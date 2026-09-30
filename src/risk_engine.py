import pandas as pd
from pathlib import Path


# -----------------------------------------
# PROJECT PATH
# -----------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "detected_security_events.csv"

OUTPUT_FILE = BASE_DIR / "data" / "security_alerts.csv"


# -----------------------------------------
# LOAD DETECTION RESULTS
# -----------------------------------------

df = pd.read_csv(INPUT_FILE)


# -----------------------------------------
# RISK SCORING FUNCTION
# -----------------------------------------

def calculate_risk(row):

    score = 0
    reasons = []

    threat = row["detected_threat"]

    # Port scanning
    if "PORT_SCAN" in threat:
        score += 30
        reasons.append("Multiple destination ports contacted")

    # Failed access
    if "FAILED_ACCESS" in threat:
        score += 25
        reasons.append("Repeated denied connections")

    # Unauthorized OT communication
    if "UNAUTHORIZED_OT" in threat:
        score += 40
        reasons.append("Untrusted source communicating with PLC")

    # Excessive Modbus traffic
    if "EXCESSIVE_MODBUS" in threat:
        score += 20
        reasons.append("High volume of Modbus communication")

    # Multiple detections
    if "," in threat:
        score += 20
        reasons.append("Multiple suspicious behaviors detected")

    # -------------------------------------
    # Severity
    # -------------------------------------

    if score == 0:
        severity = "NORMAL"

    elif score < 30:
        severity = "LOW"

    elif score < 60:
        severity = "MEDIUM"

    elif score < 85:
        severity = "HIGH"

    else:
        severity = "CRITICAL"

    return pd.Series({
        "risk_score": score,
        "severity": severity,
        "reason": "; ".join(reasons)
    })


# -----------------------------------------
# APPLY RISK ENGINE
# -----------------------------------------

risk_results = df.apply(
    calculate_risk,
    axis=1
)

df = pd.concat(
    [df, risk_results],
    axis=1
)


# -----------------------------------------
# KEEP SECURITY EVENTS
# -----------------------------------------

alerts = df[
    df["severity"] != "NORMAL"
].copy()


# -----------------------------------------
# SAVE RESULTS
# -----------------------------------------

alerts.to_csv(
    OUTPUT_FILE,
    index=False
)


# -----------------------------------------
# DISPLAY RESULTS
# -----------------------------------------

print("=" * 60)
print("OT SENTINEL - RISK ENGINE")
print("=" * 60)

print("\nSeverity Distribution:")

print(
    alerts["severity"]
    .value_counts()
)


print("\nSecurity Alerts:")

print(
    alerts[
        [
            "timestamp",
            "src_ip",
            "dst_ip",
            "detected_threat",
            "risk_score",
            "severity",
            "reason"
        ]
    ].head(20)
)


print("\nSecurity alerts saved to:")

print(OUTPUT_FILE)