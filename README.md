

# Reporting folder
Developed with Python 3.9.2

Contains Python Pandas code to generate the following visualisations from the Netflow data:

1. Total bytes consumed by protocol.
2. Total bytes consumed by the specific src IP.
3. Top ten talkers by src-dest ip pair (bytes).
4. Bytes per second as time series data.

Run generate-report.py

# Enrichment folder
Developed with Python 3.8.2

Contains Python code to enrich default netflow csv files produced by pmacct with custom data

Run enrich-netflow.py