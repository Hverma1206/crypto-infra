# Crypto Scam Infrastructure Mapper

An OSINT investigation prototype for mapping crypto scam infrastructure from public sources.

## Current Capabilities

- Ethereum wallet transaction lookup through Etherscan
- Wallet impact estimate from inbound transactions
- Certificate transparency lookup through crt.sh
- WHOIS domain intelligence and risk flags
- Wayback Machine archive lookup
- CryptoScamDB blacklist checks
- Reddit and public verification links for web mentions
- SQLite caching for faster demos
- Flask API backend
- React investigation dashboard with Cytoscape graph visualization
- Local narrative report generation

## Backend

```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Add your keys in `backend/.env`.

`ETHERSCAN_KEY` is needed for wallet analysis. Reddit keys are optional; without them, the app still shows public verification links.

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal.

## Tests

```bash
cd backend
source venv/bin/activate
python test_day4.py
python test_day5.py
python test_day6.py
python test_day7.py
```

Day 1 requires a valid Etherscan key in `.env`.

## Demo Flow

1. Start the backend with `python app.py`.
2. Start the frontend with `npm run dev`.
3. Enter a domain or wallet.
4. Review the graph, risk score, findings, evidence counts, and generated report.
