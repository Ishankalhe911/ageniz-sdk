***


# 🛡️ Ageniz SDK
**The Zero-Trust ML Risk Oracle and Firewall for Algorand AI Agents.**

[![PyPI version](https://img.shields.io/pypi/v/agenizai-sdk.svg)](https://pypi.org/project/agenizai-sdk/)
[![Python versions](https://img.shields.io/pypi/pyversions/agenizai-sdk.svg)](https://pypi.org/project/agenizai-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Ageniz is a developer-first security protocol that prevents AI Agents (like trading bots or autonomous assistants) from draining wallets through hallucinations, prompt injections, or malicious intent. 

By routing all agent transactions through an off-chain Machine Learning Oracle and validating them on-chain via an immutable Smart Contract Vault, Ageniz provides enterprise-grade "Defense in Depth."

---

## ✨ Features
* **ML Intent Scoring:** Prevents prompt-injection attacks and anomalies before they reach the blockchain.
* **Cryptographic Bait-and-Switch Protection:** Recipient addresses are bound into the Oracle's Ed25519 signature.
* **Replay Attack Immunity:** Strict, timestamp-based Nonce tracking stored in Algorand Local State.
* **Dynamic Reputation:** Agents earn trust scores over time, unlocking lower fees and higher limits.
* **Automated x402 Routing:** Seamlessly bundles security tolls and Vault payments into a single Atomic Transaction.

---

## 📦 Installation

```bash
pip install agenizai-sdk
```

---

## Quickstart

### 1. Environment Setup
Create a `.env` file in your project root with your Algorand wallet details and Ageniz configuration:

```env
# Your AI Agent's Wallet
DEPLOYER_MNEMONIC="your twenty five word algorand testnet mnemonic phrase goes here..."

# Ageniz Protocol Config
APP_ID=760267917
ORACLE_URL="https://ageniz-oracle.onrender.com"
```

### 2. Basic Implementation
Here is a complete example of initializing the agent, opting into the security contract, and executing a protected payment.

```python
import os
from dotenv import load_dotenv
from ageniz_sdk.core import AgenizSDK

load_dotenv()

# 1. Initialize the Firewall
agent = AgenizSDK(
    wallet_mnemonic=os.getenv("DEPLOYER_MNEMONIC"),
    ageniz_api_key="your_developer_api_key",
    app_id=int(os.getenv("APP_ID")),
    oracle_url=os.getenv("ORACLE_URL")
)

# 2. Opt-in to the Vault (Required once per wallet for Nonce tracking)
agent.opt_in()

# 3. Execute a Protected Payment
print("Requesting payment authorization...")

result = agent.pay(
    recipient="YZ2L7MGFX35YUGVPB2YF3S4K3KQVNJ4BWYFIB3UVMJNQAPEME3MK7ME2DU",
    amount_algo=1.0,
    context="Paying external weather API for daily data fetch."
)

# 4. Handle the Verdict
if result["status"] == "SUCCESS":
    print(f"✅ Payment cleared firewall! TxID: {result['tx_id']}")
elif result["status"] == "BLOCKED":
    print(f"❌ Payment blocked by ML Oracle: {result['reason']}")
else:
    print(f"⚠️ Transaction failed: {result.get('reason')}")
```

---

## 🔐 Architecture: The 86-Byte Fortress
Ageniz does not rely solely on off-chain AI. It enforces security on-chain using an **86-byte cryptographic payload**.

When `agent.pay()` is called:
1. The SDK sends the request context to the **Ageniz ML Oracle**.
2. If deemed `SAFE`, the Oracle generates a unique `nonce` and signs an 86-byte payload containing the exact `(amount, recipient, nonce)`.
3. The SDK bundles this signature and the transaction into an Atomic Group.
4. The **Ageniz Smart Contract** reconstructs the payload on-chain, verifies the Ed25519 signature, checks the nonce against the agent's Local State to prevent replays, and finally releases the funds.

---

## 📊 Checking Agent Reputation
You can monitor your agent's standing with the protocol at any time:

```python
status = agent.get_status()

print(f"Reputation Score : {status['reputation_score']}/100")
print(f"Velocity         : {status['velocity']} tx/hr")
print(f"Fee Tier         : {status['fee_tier']['tier']} ({status['fee_tier']['fee_pct']}%)")
```

---

## 📄 License
This project is licensed under the MIT License.


***

