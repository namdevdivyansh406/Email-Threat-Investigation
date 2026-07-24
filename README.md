# Email Threat Investigation

A simple Flask web application for uploading and analyzing .eml email files.

## Project structure

- app/__init__.py: application factory
- app/routes.py: upload handling and email parsing logic
- app/templates/: HTML templates for the upload and results pages
- app/static/css/: styling for the UI
- run.py: entry point for running the Flask app

## Run locally

1. Open the project folder:
   - cd /workspaces/Email-Threat-Investigation
2. Create and activate a virtual environment (recommended):
   - python3 -m venv .venv
   - source .venv/bin/activate
3. Install dependencies:
   - pip install -r requirements.txt
4. Start the Flask app:
   - python3 run.py
5. Open your browser at:
   - http://127.0.0.1:5000/

### What you can do
- Upload an .eml file
- Review headers, authentication results, URLs, attachments, and indicators
- Generate a PDF investigation report

The app accepts .eml uploads and analyzes headers, authentication, URLs, attachments, and extracted IOCs.