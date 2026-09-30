import pandas as pd
import numpy as np
from pathlib import Path

# Reproducible results
np.random.seed(42)

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Industrial devices
engineering_pcs = [
    "10.10.1.10",
    "10.10.1.11"
]

scada_servers = [
    "10.10.10.5",
    "10.10.10.6"
]

plcs = [
    "10.10.20.10",
    "10.10.20.11",
    "10.10.20.12"
]

normal_sources = engineering_pcs + scada_servers

rows = []

# -----------------------------------
# 1. NORMAL OT TRAFFIC
# -----------------------------------

for i in range(5000):

    source = np.random.choice(normal_sources)
    destination = np.random.choice(plcs)

    timestamp = pd.Timestamp("2026-09-01") + pd.Timedelta(
        seconds=np.random.randint(0, 30 * 24 * 60 * 60)
    )

    row = {
        "timestamp": timestamp,
        "src_ip": source,
        "dst_ip": destination,
        "protocol": "TCP",
        "dst_port": 502,
        "action": "ALLOW",
        "bytes": np.random.randint(80, 1500),
        "modbus_function": np.random.choice([1, 2, 3, 4, 16]),
        "event_type": "NORMAL"
    }

    rows.append(row)


# -----------------------------------
# 2. PORT SCAN ACTIVITY
# -----------------------------------

for i in range(150):

    source = "10.10.99.50"

    destination = np.random.choice(plcs)

    ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 502, 8080]

    timestamp = pd.Timestamp("2026-09-01") + pd.Timedelta(
        seconds=np.random.randint(0, 30 * 24 * 60 * 60)
    )

    row = {
        "timestamp": timestamp,
        "src_ip": source,
        "dst_ip": destination,
        "protocol": "TCP",
        "dst_port": np.random.choice(ports),
        "action": "DENY",
        "bytes": np.random.randint(40, 200),
        "modbus_function": 0,
        "event_type": "PORT_SCAN"
    }

    rows.append(row)


# -----------------------------------
# 3. FAILED ACCESS ATTEMPTS
# -----------------------------------

for i in range(150):

    source = "10.10.99.60"

    destination = np.random.choice(scada_servers)

    timestamp = pd.Timestamp("2026-09-01") + pd.Timedelta(
        seconds=np.random.randint(0, 30 * 24 * 60 * 60)
    )

    row = {
        "timestamp": timestamp,
        "src_ip": source,
        "dst_ip": destination,
        "protocol": "TCP",
        "dst_port": 443,
        "action": "DENY",
        "bytes": np.random.randint(40, 300),
        "modbus_function": 0,
        "event_type": "FAILED_ACCESS"
    }

    rows.append(row)


# -----------------------------------
# 4. UNAUTHORIZED OT COMMUNICATION
# -----------------------------------

for i in range(150):

    source = "10.10.50.25"

    destination = np.random.choice(plcs)

    timestamp = pd.Timestamp("2026-09-01") + pd.Timedelta(
        seconds=np.random.randint(0, 30 * 24 * 60 * 60)
    )

    row = {
        "timestamp": timestamp,
        "src_ip": source,
        "dst_ip": destination,
        "protocol": "TCP",
        "dst_port": 502,
        "action": "ALLOW",
        "bytes": np.random.randint(100, 1500),
        "modbus_function": np.random.choice([3, 5, 6, 15, 16]),
        "event_type": "UNAUTHORIZED_OT"
    }

    rows.append(row)


# -----------------------------------
# 5. EXCESSIVE MODBUS ACTIVITY
# -----------------------------------

for i in range(150):

    source = np.random.choice(engineering_pcs)

    destination = np.random.choice(plcs)

    timestamp = pd.Timestamp("2026-09-01") + pd.Timedelta(
        seconds=np.random.randint(0, 30 * 24 * 60 * 60)
    )

    row = {
        "timestamp": timestamp,
        "src_ip": source,
        "dst_ip": destination,
        "protocol": "TCP",
        "dst_port": 502,
        "action": "ALLOW",
        "bytes": np.random.randint(80, 1000),
        "modbus_function": np.random.choice([5, 6, 15, 16]),
        "event_type": "EXCESSIVE_MODBUS"
    }

    rows.append(row)


# -----------------------------------
# CREATE DATAFRAME
# -----------------------------------

df = pd.DataFrame(rows)

# Sort chronologically
df = df.sort_values("timestamp")

# Reset index
df = df.reset_index(drop=True)

# Save CSV
output_file = DATA_DIR / "ot_network_logs.csv"

df.to_csv(output_file, index=False)

print("=" * 50)
print("OT SECURITY DATASET GENERATED")
print("=" * 50)

print(f"Total events: {len(df)}")

print("\nEvent distribution:")
print(df["event_type"].value_counts())

print(f"\nSaved to:")
print(output_file)