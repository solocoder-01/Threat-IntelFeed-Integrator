
"""Threat IntelFeed Integrator — Professional SOC dashboard."""

import io
import json
import sqlite3
from pathlib import Path
from feed_status import load_feed_status
from pipeline_status import load_pipeline_status
from feed_status import get_feed_freshness
import pandas as pd
import streamlit as st


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "threat_intel.db"

MAX_EXPORT_ROWS = 1000
MAX_DB_ROWS = 100_000

VALID_TYPES = ["ipv4", "domain", "url", "sha256"]
VALID_LEVELS = ["LOW", "MEDIUM", "HIGH"]

st.set_page_config(
    page_title="Threat IntelFeed | SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------- Data access ----------

@st.cache_data(ttl=15, show_spinner=False)
def load_indicators():
    """Read indicators using a read-only SQLite connection."""
    if not DB_PATH.is_file():
        raise FileNotFoundError(
            "Database not found. Run the import pipeline first."
        )

    uri = DB_PATH.as_uri() + "?mode=ro"

    with sqlite3.connect(uri, uri=True, timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")

        rows = connection.execute(
            """
            SELECT indicator, indicator_type, sources_json,
                   source_count, average_confidence, source_bonus,
                   risk_score, risk_level, reasons_json, updated_at
            FROM indicators
            ORDER BY risk_score DESC, indicator ASC
            LIMIT ?
            """,
            (MAX_DB_ROWS,),
        ).fetchall()

    records = []

    for row in rows:
        item = dict(row)

        try:
            sources = json.loads(item["sources_json"])
            reasons = json.loads(item["reasons_json"])

            if not isinstance(sources, list) or not all(
                isinstance(source, str) for source in sources
            ):
                sources = []

            if not isinstance(reasons, list) or not all(
                isinstance(reason, str) for reason in reasons
            ):
                reasons = []

        except (TypeError, json.JSONDecodeError):
            sources, reasons = [], []

        records.append({
            "Indicator": str(item["indicator"] or ""),
            "Type": str(item["indicator_type"] or ""),
            "Sources": ", ".join(sources),
            "Source Count": item["source_count"],
            "Avg Confidence": item["average_confidence"],
            "Source Bonus": item["source_bonus"],
            "Risk Score": item["risk_score"],
            "Risk Level": str(item["risk_level"] or "").upper(),
            "Reasons": " | ".join(reasons),
            "Updated At": str(item["updated_at"] or ""),
        })

    return pd.DataFrame(records)


def safe_csv_value(value):
    """Reduce spreadsheet formula-injection risk."""
    value = str(value)

    if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value

    return value


def make_csv_export(frame):
    """Create a bounded UTF-8 CSV export."""
    if len(frame) > MAX_EXPORT_ROWS:
        raise ValueError(
            f"Export is limited to {MAX_EXPORT_ROWS} rows."
        )

    export_frame = frame.copy()

    for column in export_frame.columns:
        export_frame[column] = export_frame[column].map(safe_csv_value)

    buffer = io.StringIO(newline="")
    export_frame.to_csv(buffer, index=False, lineterminator="\n")

    return buffer.getvalue().encode("utf-8-sig")


# ---------- Sidebar ----------

with st.sidebar:
    st.title("🛡️ Threat IntelFeed")
    st.caption("SOC investigation console")
    st.divider()

    st.markdown("### Data source")
    st.code("SQLite · Read-only", language=None)
    st.caption("Local threat-intelligence database")

    if st.button("Refresh dashboard", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

        st.divider()
    st.markdown("### Risk scoring")
    st.markdown(
        """
        **HIGH (70-100)**
        Prioritize investigation.

        **MEDIUM (40-69)**
        Review supporting evidence.

        **LOW (0-39)**
        Lower priority; not automatically safe.
        """
    )

    st.divider()
    st.caption("Indicators are data, not executable files.")
    st.caption("Do not open suspicious URLs from this console.")


# ---------- Header ----------

st.title("Threat Intelligence Dashboard")
st.caption(
    "IOC enrichment · Risk-based triage · Feed attribution · Local SQLite"
)

st.info(
    "Risk scores are project heuristics for prioritization. "
    "They do not prove malicious activity or represent a probability."
)

try:
    data = load_indicators()
except (OSError, sqlite3.Error, ValueError) as error:
    st.error(f"Could not load the database: {error}")
    st.info(
        "Check data/threat_intel.db and run "
        "python import_to_db.py before starting the dashboard."
    )
    st.stop()

if data.empty:
    st.warning("No indicators found. Import sample or feed data first.")
    st.stop()

# ---------- Data quality ----------

if len(data) == MAX_DB_ROWS:
    st.warning(
        f"The dashboard is limited to {MAX_DB_ROWS:,} database records. "
        "Some records may not be shown."
    )

valid_levels = data["Risk Level"].isin(VALID_LEVELS)
valid_types = data["Type"].isin(VALID_TYPES)

if not valid_levels.all() or not valid_types.all():
    st.warning(
        "Some records contain unexpected types or risk levels. "
        "Review them before relying on the dashboard."
    )

if (data["Sources"].str.contains("URLhaus", case=False, na=False)).any():
    st.caption("URLhaus records are source-reported indicators; verify context.")

total = len(data)
high_count = int((data["Risk Level"] == "HIGH").sum())
medium_count = int((data["Risk Level"] == "MEDIUM").sum())
low_count = int((data["Risk Level"] == "LOW").sum())
source_count = len({
    source.strip()
    for value in data["Sources"]
    for source in value.split(",")
    if source.strip()
})

# ---------- KPI cards ----------

st.subheader("Security overview")

k1, k2, k3, k4 = st.columns(4)

k1.metric("Total indicators", f"{total:,}")
k2.metric("High risk", f"{high_count:,}")
k3.metric("Medium risk", f"{medium_count:,}")
k4.metric("Low risk", f"{low_count:,}")

st.caption(
    f"Distinct source names represented in records: {source_count}"
)

st.divider()

# ---------- Filters ----------

st.subheader("Investigate indicators")

with st.container(border=True):
    search_text = st.text_input(
        "Search indicator or source",
        placeholder="Search an IP, domain, URL, hash or source name",
        max_chars=256,
    )

    source_values = sorted({
        source.strip()
        for value in data["Sources"]
        for source in value.split(",")
        if source.strip()
    })

    type_values = sorted(set(data["Type"]) & set(VALID_TYPES))
    level_values = ["HIGH", "MEDIUM", "LOW"]
    present_levels = [
        level for level in level_values
        if level in set(data["Risk Level"])
    ]

    f1, f2, f3 = st.columns(3)

    with f1:
        selected_types = st.multiselect(
            "Indicator type",
            options=type_values,
            default=type_values,
        )

    with f2:
        selected_levels = st.multiselect(
            "Risk level",
            options=present_levels,
            default=present_levels,
        )

    with f3:
        selected_sources = st.multiselect(
            "Threat-intelligence source",
            options=source_values,
            default=source_values,
        )

    min_score = st.slider(
        "Minimum risk score",
        min_value=0,
        max_value=100,
        value=0,
    )

filtered = data[
    data["Type"].isin(selected_types)
    & data["Risk Level"].isin(selected_levels)
    & (data["Risk Score"] >= min_score)
].copy()

if selected_sources:
    filtered = filtered[
        filtered["Sources"].apply(
            lambda value: any(
                source in selected_sources
                for source in value.split(", ")
            )
        )
    ]
else:
    filtered = filtered.iloc[0:0]

if search_text:
    search_mask = (
        filtered["Indicator"].str.contains(
            search_text, case=False, regex=False, na=False
        )
        | filtered["Sources"].str.contains(
            search_text, case=False, regex=False, na=False
        )
    )
    filtered = filtered[search_mask]



# ---------- Pipeline monitoring ----------

st.subheader("Pipeline monitoring")

pipeline_status = load_pipeline_status()

status = pipeline_status.get("status", "UNKNOWN")
last_run = pipeline_status.get("last_run_utc")
message = pipeline_status.get("message", "")
indicator_count = pipeline_status.get("indicator_count", 0)

status_col, time_col, count_col = st.columns(3)

with status_col:
    st.metric("Pipeline status", status)

with time_col:
    st.metric("Last pipeline run (UTC)", last_run or "Not recorded")

with count_col:
    st.metric("Unique indicators processed", indicator_count)

if status == "FAILED":
    st.error(f"Last pipeline run failed: {message}")
elif status == "SUCCESS":
    st.success(message)
else:
    st.info(message or "No pipeline status has been recorded yet.")

st.divider()



# ---------- Feed freshness monitoring ----------

st.subheader("Threat feed monitoring")

feed_status = load_feed_status()

feed_name = feed_status.get("feed", "URLhaus")
status = feed_status.get("status", "UNKNOWN")
last_attempt = feed_status.get("last_attempt_utc")
indicator_count = feed_status.get("indicator_count", 0)
message = feed_status.get("message", "")

feed_col, time_col, count_col = st.columns(3)

with feed_col:
    st.metric(f"{feed_name} status", status)

with time_col:
    st.metric("Last fetch attempt (UTC)", last_attempt or "Not recorded")

with count_col:
    st.metric("Valid unique URLs fetched", indicator_count)

if status == "FAILED":
    st.error(f"{feed_name} fetch failed: {message}")
elif status == "SUCCESS":
    st.success(message)
else:
    st.info(message or "No feed-fetch attempt recorded yet.")


# ---------- Feed freshness validation ----------

freshness = get_feed_freshness(max_age_hours=24)

st.markdown("#### Feed freshness")

freshness_col, age_col = st.columns(2)

with freshness_col:
    st.metric("Freshness state", freshness["state"])

with age_col:
    age_hours = freshness["age_hours"]
    st.metric(
        "Hours since last successful fetch",
        f"{age_hours:.2f}" if age_hours is not None else "N/A",
    )

if freshness["state"] == "STALE":
    st.warning(freshness["message"])
elif freshness["state"] == "FRESH":
    st.success(freshness["message"])
else:
    st.info(freshness["message"])


st.divider()


# ---------- Analytics ----------

st.subheader("Threat analytics")

chart1, chart2 = st.columns(2)

with chart1:
    st.markdown("**Risk distribution**")

    risk_distribution = (
        filtered["Risk Level"]
        .value_counts()
        .reindex(["HIGH", "MEDIUM", "LOW"], fill_value=0)
    )

    st.bar_chart(risk_distribution, height=280)

with chart2:
    st.markdown("**Indicators by source**")

    source_counts = {}

    for value in filtered["Sources"]:
        for source in set(
            part.strip() for part in value.split(",") if part.strip()
        ):
            source_counts[source] = source_counts.get(source, 0) + 1

    source_series = pd.Series(
        source_counts, dtype="int64", name="Indicators"
    ).sort_values(ascending=False).head(10)

    if source_series.empty:
        st.caption("No sources match the selected filters.")
    else:
        st.bar_chart(source_series, height=280)

st.divider()

# ---------- Indicator table ----------

st.subheader("Indicator records")
st.caption(
    f"Showing {len(filtered):,} of {total:,} records after filtering. "
    "Indicator values are displayed as text; do not open suspicious URLs."
)

display_columns = [
    "Indicator",
    "Type",
    "Sources",
    "Source Count",
    "Avg Confidence",
    "Source Bonus",
    "Risk Score",
    "Risk Level",
    "Updated At",
]


st.subheader("Timestamp verification")

st.write("Latest timestamp in loaded data:")
st.code(str(data["Updated At"].max()))

st.write("Most recently updated records:")
st.dataframe(
    data.sort_values("Updated At", ascending=False)[
        ["Indicator", "Risk Score", "Updated At"]
    ].head(10),
    use_container_width=True,
    hide_index=True,
)

st.dataframe(
    filtered[display_columns],
    use_container_width=True,
    hide_index=True,
    height=420,
    column_config={
        "Indicator": st.column_config.TextColumn(
            "Indicator",
            help="Threat indicator displayed as text.",
            width="large",
        ),
        "Risk Score": st.column_config.ProgressColumn(
            "Risk Score",
            min_value=0,
            max_value=100,
            format="%d",
        ),
        "Avg Confidence": st.column_config.NumberColumn(
            "Avg Confidence",
            min_value=0,
            max_value=100,
            format="%d",
        ),
        "Source Bonus": st.column_config.NumberColumn(
            "Source Bonus",
            format="%d",
        ),
    },
)

# ---------- Indicator investigation ----------

st.subheader("Indicator investigation")

if filtered.empty:
    st.info("No indicators match your current filters.")
else:
    selected_indicator = st.selectbox(
        "Choose an indicator to inspect",
        options=filtered["Indicator"].tolist(),
    )

    selected_record = filtered[
        filtered["Indicator"] == selected_indicator
    ].iloc[0]

    with st.container(border=True):
        st.markdown("**Indicator value — plain text**")
        st.text(selected_record["Indicator"])

        d1, d2, d3 = st.columns(3)
        d1.metric("Risk score", int(selected_record["Risk Score"]))
        d2.metric("Risk level", selected_record["Risk Level"])
        d3.metric("Source count", int(selected_record["Source Count"]))

        st.markdown("**Indicator details**")
        st.write(f"**Type:** {selected_record['Type']}")
        st.write(f"**Sources:** {selected_record['Sources']}")
        st.write(
            f"**Average confidence:** "
            f"{selected_record['Avg Confidence']}"
        )
        st.write(f"**Source bonus:** {selected_record['Source Bonus']}")
        st.write(f"**Last updated:** {selected_record['Updated At']}")

        st.markdown("**Scoring explanation**")

        reasons = [
            reason.strip()
            for reason in selected_record["Reasons"].split("|")
            if reason.strip()
        ]

        if reasons:
            for reason in reasons:
                st.markdown(f"- {reason}")
        else:
            st.caption("No scoring explanation is available.")

        st.warning(
            "A high score is not proof of compromise. Confirm the "
            "indicator against reliable evidence before taking action."
        )

# ---------- Export ----------

st.divider()
st.subheader("Export filtered results")

if filtered.empty:
    st.caption("No matching records to export.")
elif len(filtered) > MAX_EXPORT_ROWS:
    st.warning(
        f"Export is limited to {MAX_EXPORT_ROWS:,} rows. "
        "Narrow the filters before exporting."
    )
else:
    try:
        csv_bytes = make_csv_export(filtered)

        st.download_button(
            "Download filtered CSV",
            data=csv_bytes,
            file_name="threat_intel_filtered.csv",
            mime="text/csv",
        )
    except (ValueError, UnicodeError) as error:
        st.error(f"CSV export failed: {error}")

with st.expander("Scoring methodology and limitations"):
    st.markdown(
        """
        - **HIGH (70–100):** prioritize investigation.
        - **MEDIUM (40–69):** review context and supporting evidence.
        - **LOW (0–39):** lower priority, but not automatically safe.
        - The project calculates average source confidence plus a
          corroboration bonus capped at 20 points, with a maximum score
          of 100.
        - URLhaus confidence value 80 in this project is a local heuristic,
          not an official URLhaus confidence score.
        - Multiple feeds may copy one another. Source count alone does
          not establish independent corroboration.
        - A listed URL may become inactive or its classification may change.
        - Never block an asset or declare a compromise based solely on
          this heuristic score.
        """
    )

st.caption(
    "Threat IntelFeed Integrator · Local SOC portfolio project · "
    "Database accessed in read-only mode"
)
