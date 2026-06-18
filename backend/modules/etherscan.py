import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("etherscan")

API_KEY = os.getenv("ETHERSCAN_KEY")
BASE_URL = "https://api.etherscan.io/v2/api"

if not API_KEY:
    logger.warning("ETHERSCAN_KEY is not set — wallet analysis will return empty results")


def _get(params: dict) -> dict:
    """
    Internal helper. Makes one GET request to Etherscan.
    Adds the API key automatically to every call.
    Returns the parsed JSON or an empty dict on failure.
    """
    params["apikey"] = API_KEY
    try:
        response = requests.get(BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        logger.warning("Request timed out")
        return {}
    except requests.exceptions.RequestException as e:
        logger.warning("Request failed: %s", e)
        return {}


def get_transactions(address: str, limit: int = 20) -> list:
    """
    Fetch the most recent normal transactions for a wallet address.

    Returns a list of transaction dicts, each containing:
      - hash        : unique transaction ID
      - from        : sender wallet address
      - to          : receiver wallet address
      - value       : amount in Wei (divide by 1e18 to get ETH)
      - timeStamp   : Unix timestamp string
      - isError     : '0' = success, '1' = failed
    """
    data = _get({
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "page": 1,
        "offset": limit,
        "sort": "desc",   # most recent first
        "chainid": 1,
    })

    if data.get("status") == "1":
        return data.get("result", [])
    else:
        logger.info("No transactions returned for %s: %s", address, data.get("message", "unknown"))
        return []


def get_contract_info(address: str) -> dict:
    """
    Check if a wallet address is actually a smart contract.
    If it is, returns the contract's source code metadata and
    most importantly: who CREATED it (the deployer wallet).

    Returns dict with keys:
      - is_contract   : True / False
      - contract_name : name of the token/contract if verified
      - deployer      : wallet address that deployed this contract
                        (this is your key lead — same person as the scammer)
    """
    # Step 1: Check if it's a contract by fetching its bytecode
    bytecode_data = _get({
        "module": "proxy",
        "action": "eth_getCode",
        "address": address,
        "tag": "latest",
    })

    bytecode = bytecode_data.get("result", "0x")
    is_contract = len(bytecode) > 4  # "0x" alone = not a contract

    result = {
        "is_contract": is_contract,
        "contract_name": None,
        "deployer": None,
    }

    if not is_contract:
        return result

    # Step 2: Get verified source info (name, compiler, etc.)
    source_data = _get({
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
    })

    if source_data.get("status") == "1":
        info = source_data.get("result", [{}])[0]
        result["contract_name"] = info.get("ContractName") or "Unverified"

    # Step 3: Find the deployment transaction to get the deployer
    # The deployer is in the "from" field of the transaction where "to" is empty
    tx_data = _get({
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "page": 1,
        "offset": 10,
        "sort": "asc",   # oldest first — deployment is the first tx
    })

    if tx_data.get("status") == "1":
        txs = tx_data.get("result", [])
        for tx in txs:
            # Contract creation tx has empty "to" field
            if tx.get("to") == "" or tx.get("to") is None:
                result["deployer"] = tx.get("from")
                break

    return result


def get_balance(address: str) -> float:
    """
    Get the current ETH balance of a wallet in ETH (not Wei).
    Useful for the victim impact panel — shows how much ETH
    is still sitting in the scam wallet.
    """
    data = _get({
        "module": "account",
        "action": "balance",
        "address": address,
        "tag": "latest",
    })

    if data.get("status") == "1":
        wei = int(data.get("result", 0))
        return wei / 1e18   # convert Wei → ETH
    return 0.0


def compute_victim_impact(transactions: list) -> dict:
    """
    Given a list of transactions INTO a scam wallet,
    compute victim impact statistics.

    This is your 'Victim Impact' feature — no extra API call needed,
    just math on the transaction data you already fetched.

    Returns:
      - total_eth_received : total ETH sent TO this wallet
      - unique_senders     : number of unique addresses that sent money
                             (this is your VICTIM COUNT ESTIMATE)
      - first_seen         : Unix timestamp of earliest transaction
      - last_seen          : Unix timestamp of most recent transaction
      - days_active        : how many days the scam has been running
    """
    if not transactions:
        return {
            "total_eth_received": 0,
            "unique_senders": 0,
            "first_seen": None,
            "last_seen": None,
            "days_active": 0,
        }

    senders = set()
    total_wei = 0
    timestamps = []

    for tx in transactions:
        # Only count successful incoming transactions (value > 0)
        if tx.get("isError") == "0" and int(tx.get("value", 0)) > 0:
            senders.add(tx["from"])
            total_wei += int(tx["value"])
            timestamps.append(int(tx["timeStamp"]))

    if not timestamps:
        return {
            "total_eth_received": 0,
            "unique_senders": 0,
            "first_seen": None,
            "last_seen": None,
            "days_active": 0,
        }

    first_ts = min(timestamps)
    last_ts = max(timestamps)
    days_active = max(1, (last_ts - first_ts) // 86400)

    return {
        "total_eth_received": round(total_wei / 1e18, 4),
        "unique_senders": len(senders),
        "first_seen": first_ts,
        "last_seen": last_ts,
        "days_active": days_active,
    }


def analyze_wallet(address: str) -> dict:
    """
    MAIN FUNCTION — call this from app.py.

    Given any wallet address, returns everything your tool needs:
      - transactions   : list of recent transactions
      - contract_info  : is it a contract? who deployed it?
      - balance        : current ETH balance
      - impact         : victim impact statistics
      - connected      : list of unique addresses this wallet interacted with
                         (used to build graph edges in graph_builder.py)
    """
    logger.info("Analyzing wallet: %s", address)

    transactions = get_transactions(address, limit=50)
    contract_info = get_contract_info(address)
    balance = get_balance(address)
    impact = compute_victim_impact(transactions)

    # Extract all unique addresses this wallet talked to
    # These become nodes in your graph
    connected_addresses = set()
    for tx in transactions:
        if tx.get("from") and tx["from"].lower() != address.lower():
            connected_addresses.add(tx["from"])
        if tx.get("to") and tx["to"].lower() != address.lower():
            connected_addresses.add(tx["to"])

    return {
        "address": address,
        "balance_eth": balance,
        "transactions": transactions,
        "contract_info": contract_info,
        "impact": impact,
        "connected_addresses": list(connected_addresses),
    }