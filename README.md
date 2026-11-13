# AI-Powered Phishing URL & OSINT Threat Analyzer

A hybrid cybersecurity triage tool combining lexical URL analysis, WHOIS OSINT lookups, live DOM scraping, and Generative AI semantic analysis to detect phishing and brand impersonation.

## Tech Stack
- **Language:** Python 3.13
- **OSINT & Scraping:** `tldextract`, `python-whois`, `requests`, `BeautifulSoup4`
- **AI & Schema Validation:** Google GenAI SDK (`gemini-3.5-flash-lite` / `gemini-3.8-flash`), `Pydantic`
- **CLI Dashboard:** `Rich`

## Setup & Usage
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt