\# Threat-IntelFeed-Integrator

A Python-based threat intelligence integration project that collects indicators of compromise (IOCs), normalizes and deduplicates them, calculates risk scores, stores the results in SQLite, and displays monitoring information through a Streamlit dashboard.

\## Features

\- URLhaus threat-feed integration

\- IOC normalization and deduplication

\- Risk scoring and risk-level classification

\- SQLite database storage

\- Streamlit dashboard for IOC and feed monitoring

\- Pipeline execution status tracking

\- Feed-fetch status and freshness monitoring

\- Automated tests for feed status and failure handling

\## Technology Stack

\- Python

\- Streamlit

\- SQLite

\- Requests

\- CSV and JSON

\- Pytest

\## Pipeline Workflow

1\. Fetch URL indicators from URLhaus.

2\. Load sample and feed indicators.

3\. Validate and normalize indicators.

4\. Deduplicate indicators and combine source information.

5\. Calculate risk scores.

6\. Import or update indicators in the SQLite database.

7\. Display indicator and monitoring information in the dashboard.

\## Project Structure

\- `core/` — normalization, risk scoring, and database logic

\- `data/` — input data and generated outputs

\- `tests/` — automated tests

\- `fetch\_urlhaus.py` — URLhaus feed collection

\- `run\_pipeline.py` — end-to-end processing pipeline

\- `app.py` — Streamlit dashboard

\- `feed\_status.py` — feed status and freshness logic

\- `pipeline\_status.py` — pipeline execution status

\## Setup

Create and activate a virtual environment:

```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

```

Install dependencies using the project's dependency file, if available. If a `requirements.txt` file does not exist, create one containing the dependencies actually used by the project.

Configure the URLhaus authentication key using the `URLHAUS\_AUTH\_KEY` environment variable. Never commit real API keys or `.env` files.

\## Run the Project

Fetch the feed:

```powershell

python fetch\_urlhaus.py

```

Run the processing pipeline:

```powershell

python run\_pipeline.py

```

Launch the dashboard:

```powershell

python -m streamlit run app.py

```

Run automated tests:

```powershell

python -m pytest -v

```

\## Risk Scoring Note

Risk scores are calculated using this project's scoring logic. They are prioritization signals, not proof that an indicator is malicious or currently active.

\## Feed Freshness Note

The current freshness indicator measures elapsed time since the last successful feed fetch. It does not independently establish the publication age or current malicious status of each IOC.

\## Security and Data Handling

\- Keep authentication keys out of source control.

\- Do not execute or visit suspicious URLs directly.

\- Review generated data and database files before sharing the repository.

\- Use the project for authorized security research and defensive analysis.

\## Project Status

The end-to-end pipeline has completed successfully with 1,005 unique indicators in the current test run. Rerun the pipeline and tests before publishing to confirm the latest status.

## Author

SUJEET KUMAR
LinkedIn: https://www.linkedin.com/in/sujeet0123/
