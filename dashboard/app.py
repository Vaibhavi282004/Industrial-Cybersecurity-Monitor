import streamlit as st
import pandas as pd


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="OT Sentinel",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# CSS
# =========================================================

st.markdown("""
<style>

.stApp {
    background-color: #0e1117;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
}


/* Header */

.main-title {
    color: white;
    font-size: 38px;
    font-weight: 700;
    margin-bottom: 5px;
}

.sub-title {
    color: #9aa4b2;
    font-size: 17px;
    margin-bottom: 45px;
}


/* Section titles */

.section-title {
    color: white;
    font-size: 24px;
    font-weight: 700;
    margin-top: 30px;
    margin-bottom: 20px;
}


/* Metric cards */

.metric-card {
    background-color: white;
    border-radius: 14px;
    padding: 22px;
    height: 130px;
    box-sizing: border-box;
    border: 1px solid #e5e7eb;
}

.metric-title {
    color: #667085;
    font-size: 15px;
    margin-bottom: 18px;
}

.metric-number {
    color: #111827;
    font-size: 36px;
    font-weight: 700;
}


/* Security status */

.status-box {
    background-color: #3b1d1d;
    border-left: 6px solid #ff4b4b;
    border-radius: 12px;
    padding: 22px;
    margin-bottom: 30px;
}

.status-title {
    color: white;
    font-size: 18px;
    font-weight: 700;
}

.status-text {
    color: #eeeeee;
    font-size: 15px;
    margin-top: 10px;
}


/* Dataframe */

[data-testid="stDataFrame"] {
    border-radius: 10px;
}


/* Charts */

h4 {
    color: white !important;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# HEADER
# =========================================================

st.markdown(
    '<div class="main-title">🛡️ OT Sentinel</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="sub-title">Industrial Operational Technology Security Monitoring Dashboard</div>',
    unsafe_allow_html=True
)


# =========================================================
# SECURITY OVERVIEW
# =========================================================

st.markdown(
    '<div class="section-title">Security Overview</div>',
    unsafe_allow_html=True
)


col1, col2, col3, col4 = st.columns(4)


with col1:
    st.markdown(
        '<div class="metric-card"><span class="metric-title">Network Events</span><br><span class="metric-number">450</span></div>',
        unsafe_allow_html=True
    )


with col2:
    st.markdown(
        '<div class="metric-card"><span class="metric-title">Security Alerts</span><br><span class="metric-number">450</span></div>',
        unsafe_allow_html=True
    )


with col3:
    st.markdown(
        '<div class="metric-card"><span class="metric-title">High Severity</span><br><span class="metric-number">295</span></div>',
        unsafe_allow_html=True
    )


with col4:
    st.markdown(
        '<div class="metric-card"><span class="metric-title">Critical</span><br><span class="metric-number">5</span></div>',
        unsafe_allow_html=True
    )


# =========================================================
# SECURITY STATUS
# =========================================================

st.markdown(
    '<div class="section-title">Security Status</div>',
    unsafe_allow_html=True
)


st.markdown(
    '<div class="status-box"><span class="status-title">🚨 Attention Required</span><div class="status-text">5 Critical security alerts detected. Immediate investigation recommended.</div></div>',
    unsafe_allow_html=True
)


# =========================================================
# OT ASSET INVENTORY
# =========================================================

st.markdown(
    '<div class="section-title">OT Asset Inventory</div>',
    unsafe_allow_html=True
)


assets = pd.DataFrame({
    "Asset ID": [
        "PLC-001",
        "HMI-002",
        "SCADA-003",
        "RTU-004",
        "PLC-005"
    ],

    "Asset Type": [
        "PLC Controller",
        "Human Machine Interface",
        "SCADA Server",
        "Remote Terminal Unit",
        "PLC Controller"
    ],

    "Location": [
        "Production Line A",
        "Control Room",
        "Data Center",
        "Remote Site",
        "Production Line B"
    ],

    "Risk Level": [
        "High",
        "Medium",
        "Critical",
        "Low",
        "High"
    ]
})


st.dataframe(
    assets,
    use_container_width=True,
    hide_index=True
)


# =========================================================
# THREAT ANALYTICS
# =========================================================

st.markdown(
    '<div class="section-title">Threat Analytics</div>',
    unsafe_allow_html=True
)


col1, col2 = st.columns(2)


# ---------------------------------------------------------
# SEVERITY CHART
# ---------------------------------------------------------

with col1:

    st.markdown("#### Alert Severity Distribution")

    severity = pd.DataFrame({
        "Severity": [
            "Critical",
            "High",
            "Medium",
            "Low"
        ],

        "Count": [
            5,
            295,
            120,
            30
        ]
    })

    st.bar_chart(
        severity.set_index("Severity")
    )


# ---------------------------------------------------------
# NETWORK EVENTS
# ---------------------------------------------------------

with col2:

    st.markdown("#### Network Security Events")

    events = pd.DataFrame({
        "Time": [
            "08:00",
            "10:00",
            "12:00",
            "14:00",
            "16:00",
            "18:00"
        ],

        "Alerts": [
            20,
            45,
            80,
            60,
            100,
            75
        ]
    })

    st.line_chart(
        events.set_index("Time")
    )


# =========================================================
# FOOTER
# =========================================================

st.markdown(
    """
    <br><br>
    <div style="text-align:center; color:#667085; font-size:13px;">
        OT Sentinel | Industrial Cybersecurity Monitoring Platform
    </div>
    """,
    unsafe_allow_html=True
)