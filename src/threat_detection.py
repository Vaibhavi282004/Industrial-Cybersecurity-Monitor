import pandas as pd

INPUT_FILE = "data/ot_network_logs.csv"
OUTPUT_FILE = "data/detected_security_events.csv"

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

PLC_IPS = {
    "10.10.20.10",
    "10.10.20.11",
    "10.10.20.12"
}

TRUSTED_OT_SOURCES = {
    "10.10.1.10",
    "10.10.1.11",
    "10.10.10.5",
    "10.10.10.6"
}

MODBUS_PORT = 502

PORT_SCAN_THRESHOLD = 5
FAILED_ACCESS_THRESHOLD = 8
MODBUS_RATE_THRESHOLD = 40

# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------

df = pd.read_csv(INPUT_FILE)

df["timestamp"] = pd.to_datetime(df["timestamp"])

df = df.sort_values("timestamp").reset_index(drop=True)

df["detected_threat"] = ""

# --------------------------------------------------
# 1. PORT SCAN DETECTION
# --------------------------------------------------
# A source contacting many different ports
# is treated as a possible port scan.

port_counts = (
    df.groupby("src_ip")["dst_port"]
    .nunique()
)

port_scan_sources = set(
    port_counts[
        port_counts >= PORT_SCAN_THRESHOLD
    ].index
)

port_scan_mask = (
    df["src_ip"].isin(port_scan_sources)
    & (df["action"] == "DENY")
)

df.loc[
    port_scan_mask,
    "detected_threat"
] = "PORT_SCAN"

# --------------------------------------------------
# 2. FAILED ACCESS DETECTION
# --------------------------------------------------
# Require repeated denied connections to the
# same destination and port.
#
# This prevents port-scan traffic from being
# incorrectly classified as failed access.

failed_access_counts = (
    df[df["action"] == "DENY"]
    .groupby(
        ["src_ip", "dst_ip", "dst_port"]
    )
    .size()
)

failed_access_pairs = set(
    failed_access_counts[
        failed_access_counts >= FAILED_ACCESS_THRESHOLD
    ].index
)

failed_access_mask = df.apply(
    lambda row:
    (
        row["src_ip"],
        row["dst_ip"],
        row["dst_port"]
    ) in failed_access_pairs
    and row["action"] == "DENY",
    axis=1
)

df.loc[
    failed_access_mask,
    "detected_threat"
] = df.loc[
    failed_access_mask,
    "detected_threat"
].apply(
    lambda x:
    "FAILED_ACCESS"
    if x == ""
    else x + ",FAILED_ACCESS"
)

# --------------------------------------------------
# 3. UNAUTHORIZED OT DETECTION
# --------------------------------------------------
# Detect communication with PLCs from
# untrusted sources using Modbus/TCP.

unauthorized_mask = (
    df["dst_ip"].isin(PLC_IPS)
    & ~df["src_ip"].isin(TRUSTED_OT_SOURCES)
    & (df["dst_port"] == MODBUS_PORT)
)

df.loc[
    unauthorized_mask,
    "detected_threat"
] = df.loc[
    unauthorized_mask,
    "detected_threat"
].apply(
    lambda x:
    "UNAUTHORIZED_OT"
    if x == ""
    else x + ",UNAUTHORIZED_OT"
)

# --------------------------------------------------
# 4. EXCESSIVE MODBUS DETECTION
# --------------------------------------------------
# Detect unusually high Modbus communication
# between the same source and destination.
#
# Trusted sources are excluded from this rule
# because normal industrial systems may have
# high Modbus traffic.

modbus_df = df[
    df["dst_port"] == MODBUS_PORT
].copy()

modbus_pair_counts = (
    modbus_df
    .groupby(["src_ip", "dst_ip"])
    .size()
)

suspicious_pairs = set(
    modbus_pair_counts[
        modbus_pair_counts >= MODBUS_RATE_THRESHOLD
    ].index
)

modbus_mask = df.apply(
    lambda row:
    (
        row["src_ip"],
        row["dst_ip"]
    ) in suspicious_pairs
    and row["src_ip"] not in TRUSTED_OT_SOURCES
    and row["dst_port"] == MODBUS_PORT,
    axis=1
)

df.loc[
    modbus_mask,
    "detected_threat"
] = df.loc[
    modbus_mask,
    "detected_threat"
].apply(
    lambda x:
    "EXCESSIVE_MODBUS"
    if x == ""
    else x + ",EXCESSIVE_MODBUS"
)

# --------------------------------------------------
# SAVE DETECTED EVENTS
# --------------------------------------------------

detected = df[
    df["detected_threat"] != ""
].copy()

detected.to_csv(
    OUTPUT_FILE,
    index=False
)

# --------------------------------------------------
# RESULTS
# --------------------------------------------------

print("=" * 60)
print("OT SENTINEL - THREAT DETECTION")
print("=" * 60)

print(
    "\nTotal network events:",
    len(df)
)

print(
    "Detected suspicious events:",
    len(detected)
)

print("\nThreat distribution:")

print(
    detected["detected_threat"]
    .str.split(",")
    .explode()
    .value_counts()
)

print("\nSample detected events:")

print(
    detected[
        [
            "timestamp",
            "src_ip",
            "dst_ip",
            "dst_port",
            "event_type",
            "detected_threat"
        ]
    ].head(10).to_string(index=False)
)

print("\nSaved to:")
print(OUTPUT_FILE)