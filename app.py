import streamlit as st
import pandas as pd
import plotly.express as px

from splunk_connector import (
    get_splunk_alerts,
    run_splunk_query
)

from python_logic import process_alert
from ai_analyzer import generate_ai_analysis

st.set_page_config(
    page_title="SOC Security Analytics Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Security Analytics Dashboard")

alerts = get_splunk_alerts()

processed_alerts = [
    process_alert(alert)
    for alert in alerts
]

critical_count = len([
    x for x in processed_alerts
    if x["Severity"] == "Critical"
])

high_count = len([
    x for x in processed_alerts
    if x["Severity"] == "High"
])

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Unique Threats",
    len(processed_alerts)
)

col2.metric(
    "Critical Threats",
    critical_count
)

col3.metric(
    "High Threats",
    high_count
)

col4.metric(
    "Total Alerts",
    len(alerts)
)
st.markdown("---")

severity_df = pd.DataFrame(processed_alerts)

severity_counts = (
    severity_df["Severity"]
    .value_counts()
    .reset_index()
)

severity_counts.columns = [
    "Severity",
    "Count"
]

fig = px.pie(
    severity_counts,
    values="Count",
    names="Severity",
    title="Threat Severity Distribution",
    hole=0.5
)

fig.update_traces(
    textposition="inside",
    textinfo="percent+label"
)

st.plotly_chart(
    fig,
    use_container_width=True
)
st.markdown("---")

csv = pd.DataFrame(
    processed_alerts
).to_csv(index=False)

st.download_button(
    label="📥 Download Threat Report",
    data=csv,
    file_name="threat_report.csv",
    mime="text/csv"
)

st.markdown("---")

for threat in processed_alerts:

    st.subheader(threat["Threat_ID"])

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "Severity",
        threat["Severity"]
    )

    c2.metric(
        "Risk Score",
        threat["Risk_Score"]
    )

    c3.metric(
        "MITRE",
        threat["MITRE_ID"]
    )

    st.write(
        f"Source IP: {threat['Source_IP']}"
    )

    st.write(
        f"Username: {threat['Username']}"
    )

    st.write(
        f"Attack Type: {threat['Attack_Type']}"
    )

    threat_key = f"analysis_{threat['Threat_ID']}"

# Only show AI for High/Critical threats

    if threat["Severity"] in ["Critical", "High"]:

        if st.button(
            f"🤖 Analyze {threat['Threat_ID']}",
            key=f"btn_{threat['Threat_ID']}"
        ):

            with st.spinner(
                "Generating AI Analysis..."
            ):

                if threat_key not in st.session_state:

                    st.session_state[
                        threat_key
                    ] = generate_ai_analysis(
                        threat
                    )

        if threat_key in st.session_state:

            st.success(
                "AI Security Analysis"
            )

            st.markdown(
                st.session_state[
                    threat_key
                ]
            )

    else:

        st.info(
            "AI Analysis available only for High and Critical threats."
        )

    st.markdown("---")

st.header("Custom SPL Query")

user_query = st.text_area(
    "Enter SPL Query",
    value='''
search index=* source="ssh_logs_1000.txt"
| stats count
'''
)

if st.button("Run Query"):

    results = run_splunk_query(
        user_query
    )

    if results:

        df = pd.DataFrame(results)

        st.dataframe(
            df,
            use_container_width=True
        )

    else:

        st.warning(
            "No results returned."
        )