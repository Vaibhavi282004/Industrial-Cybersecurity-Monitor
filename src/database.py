import sqlite3
import pandas as pd

DB_FILE = "data/ot_sentinel.db"

DETECTED_FILE = "data/detected_security_events.csv"
ALERTS_FILE = "data/security_alerts.csv"


def create_database():
    conn = sqlite3.connect(DB_FILE)

    detected = pd.read_csv(DETECTED_FILE)
    alerts = pd.read_csv(ALERTS_FILE)

    detected.to_sql(
        "security_events",
        conn,
        if_exists="replace",
        index=False
    )

    alerts.to_sql(
        "security_alerts",
        conn,
        if_exists="replace",
        index=False
    )

    conn.close()

    print("=" * 60)
    print("OT SENTINEL - DATABASE")
    print("=" * 60)

    print("\nDatabase created:")
    print(DB_FILE)

    print("\nSecurity events:", len(detected))
    print("Security alerts:", len(alerts))

    print("\nTables created:")
    print("- security_events")
    print("- security_alerts")


if __name__ == "__main__":
    create_database()