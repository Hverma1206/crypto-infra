# Crypto Scam Mapper

An OSINT investigation tool for mapping crypto scam from public sources. Enter a single artifact — a wallet address, domain, or token — and the tool automatically traces connections across **6 public intelligence sources**, builds an interactive relationship graph, computes a risk score, and generates an investigation report.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  React Dashboard  (Vite + Cytoscape.js)                             │
│  Dark theme · Interactive graph · Risk panel · Report generator     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ REST API
┌──────────────────────────────┴──────────────────────────────────────┐
│  Flask Backend                                                       │
│  ┌───────────┐ ┌────────┐ ┌───────┐ ┌─────────┐ ┌───────┐ ┌─────┐ │
│  │ Etherscan │ │ crt.sh │ │ WHOIS │ │ Wayback │ │ScamDB │ │ Web │ │
│  └─────┬─────┘ └───┬────┘ └───┬───┘ └────┬────┘ └───┬───┘ └──┬──┘ │
│        └────────────┴──────────┴──────────┴──────────┴────────┘     │
│                         Graph Builder + Risk Scorer                  │
│                         SQLite Cache Layer                           │
└─────────────────────────────────────────────────────────────────────┘
```

## Intelligence Sources

| Source | Data | API Key Required |
|--------|------|:---:|
| **Etherscan** | Wallet transactions, contract deployer, balance, victim impact | Yes |
| **crt.sh** | Certificate transparency logs — subdomains, sibling domains | No |
| **WHOIS** | Domain registration, registrant email, domain age, risk flags | No |
| **Wayback Machine** | Archived snapshots, operational timeline | No |
| **CryptoScamDB** | Scam address/domain blacklist matching | No |
| **Reddit + Web** | Public discussions, ChainAbuse/Etherscan verification links | Optional |

## Getting Started

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # Edit with your API keys
python app.py
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal (default: `http://localhost:5173`).

## Environment Variables

| Variable | Required | Description |
|----------|:---:|-------------|
| `ETHERSCAN_KEY` | Yes | Free API key from [etherscan.io](https://etherscan.io/apis) |
| `REDDIT_CLIENT_ID` | No | Reddit app client ID for discussion search |
| `REDDIT_SECRET` | No | Reddit app secret |
| `GEMINI_API_KEY` | No | Google Gemini API key for AI-generated report narratives |
| `GEMINI_MODEL` | No | Model name (default: `gemini-2.5-flash`) |
| `PORT` | No | Backend port (default: `5000`) |
| `FLASK_DEBUG` | No | Enable debug mode (default: `false`) |
| `ALLOWED_ORIGINS` | No | Comma-separated CORS origins (default: `*`) |
| `LOG_LEVEL` | No | Logging level: DEBUG, INFO, WARNING, ERROR (default: `INFO`) |

## Tests

```bash
cd backend
source venv/bin/activate
python test_day4.py   # Wayback Machine
python test_day5.py   # ScamDB + Web mentions
python test_day6.py   # Cache layer
python test_day7.py   # Full domain analysis
```

## Demo Flow

1. Start the backend with `python app.py`
2. Start the frontend with `npm run dev`
3. Enter a domain (e.g., `example.com`) or a wallet address
4. Review the interactive graph, risk score, findings, evidence counts, and generated report
5. Click any graph node to inspect its details
6. Click **Generate** to produce an AI-powered investigation narrative

## Risk Scoring

The tool computes a composite risk score (0–100) from multiple signals:

| Signal | Points |
|--------|:---:|
| Matched CryptoScamDB blacklist | +40 |
| ≥10 unique sender wallets (victim indicator) | +15 |
| ≥1 ETH received | +10 |
| Domain registered < 30 days ago | +15 |
| Registrant privacy-protected | +10 |
| Short Wayback archive window (≤30 days) | +10 |
| Reddit scam discussions found | +10 |

Levels: **LOW** (0–24) · **MEDIUM** (25–49) · **HIGH** (50–74) · **CRITICAL** (75–100)

## License

This project is an academic prototype built for cybersecurity research and education.
