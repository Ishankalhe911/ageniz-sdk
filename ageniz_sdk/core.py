"""
Ageniz SDK — v2.2.0
Zero-trust ML Risk Oracle and Firewall for Algorand AI Agents

Architecture:
- Agent calls pay() for every payment
- Oracle scores transaction via ML (Velocity tracked strictly server-side)
- If SAFE, Agent routes the payment through the Ageniz Smart Contract firewall
- The contract mathematically enforces the Oracle's signature and daily limits

Transaction group (exactly 3):
  Txn 0: execute_payment() ABI call — contract verifies signature & enforces limits
  Txn 1: Agent pays Vendor directly (Non-Custodial)
  Txn 2: 0.05 ALGO flat fee to Ageniz treasury
"""

import os
import base64
import requests
import time
from dotenv import load_dotenv
from algosdk import mnemonic, account
from algosdk.atomic_transaction_composer import (
    AtomicTransactionComposer,
    AccountTransactionSigner,
    TransactionWithSigner
)
from algosdk.v2client import algod
from algosdk.abi import Method
from algosdk.transaction import PaymentTxn, OnComplete

load_dotenv()

ALGOD_URL        = "https://testnet-api.algonode.cloud"
ORACLE_URL       = os.getenv("ORACLE_URL", "https://ageniz-backend.onrender.com")
APP_ID           = int(os.getenv("APP_ID", 763708265)) # Updated to the new Router App ID
AGENIZ_TREASURY  = "EUKRBWJBKMYRCRQOHFGEUMXGK2JDXESZ5A2W5SJVJVTF7BW5CWBSUG422Q"


class AgenizSDK:
    def __init__(
        self,
        wallet_mnemonic:  str,
        ageniz_api_key:   str   = "test_key",
        app_id:           int   = APP_ID,
        oracle_url:       str   = ORACLE_URL,
        daily_cap_algo:   float = 50.0
    ):
        self.private_key    = mnemonic.to_private_key(wallet_mnemonic)
        self.address        = account.address_from_private_key(self.private_key)
        self.signer         = AccountTransactionSigner(self.private_key)

        self.api_key        = ageniz_api_key
        self.app_id         = app_id
        self.oracle_url     = oracle_url
        self.daily_cap_algo = daily_cap_algo
        self.algod_client   = algod.AlgodClient("", ALGOD_URL)

        # Velocity tracking (Purely for local UI/Demo display now)
        self._tx_count      = 0
        self._last_tx_time  = None
        self._session_start = time.time()

        # Reputation (in-memory)
        self.reputation_score = 0

        print(f"✅ AgenizSDK v3.0.0 initialized (Pure Router Edition)")
        print(f"   Agent Address : {self.address}")
        print(f"   App ID        : {self.app_id}")
        print(f"   Oracle        : {self.oracle_url}")
        print(f"   Treasury      : {AGENIZ_TREASURY}")

    def opt_in(self) -> bool:
        print(f"\n🔌 [SDK] Opting in to App ID: {self.app_id}...")
        sp = self.algod_client.suggested_params()

        atc = AtomicTransactionComposer()
        atc.add_method_call(
            app_id=self.app_id,
            method=Method.from_signature("opt_in()void"),
            sender=self.address,
            sp=sp,
            signer=self.signer,
            method_args=[],
            on_complete=OnComplete.OptInOC
        )

        try:
            result = atc.execute(self.algod_client, 4)
            print(f"✅ Opt-in successful! TxID: {result.tx_ids[0]}")
            return True
        except Exception as e:
            if "already opted in" in str(e).lower():
                print("✅ Already opted in.")
                return True
            print(f"❌ Opt-in failed: {e}")
            return False

    def pay(
        self,
        recipient:    str,
        amount_algo:  float,
        context:      str = ""
    ) -> dict:
        amount_micro = int(amount_algo * 1_000_000)

        print(f"\n{'='*50}")
        print(f"🤖 [SDK] Payment Request")
        print(f"   Recipient : {recipient}")
        print(f"   Amount    : {amount_algo} ALGO ({amount_micro} microALGO)")
        print(f"{'='*50}")

        print(f"\n🛡️  [SDK → Oracle] Requesting ML attestation...")

        try:
            oracle_res  = requests.post(
                f"{self.oracle_url}/attest",
                json={
                    "agent_address":     self.address,
                    "recipient_address": recipient,
                    "amount_micro":      amount_micro,
                    "api_key":           self.api_key,
                },
                timeout=15
            )
            oracle_data = oracle_res.json()
        except Exception as e:
            print(f"❌ [SDK] Oracle unreachable: {e}")
            return {"status": "ERROR", "reason": str(e)}

        verdict = oracle_data.get("verdict")
        score   = oracle_data.get("confidence_score")

        print(f"   Verdict          : {verdict}")
        print(f"   Confidence Score : {score}")
        print(f"   Debug            : {oracle_data.get('debug')}")

        if verdict in ("BLOCKED", "ANOMALY", "INVALID"):
            reason = oracle_data.get("debug", {}).get("reason", "Anomaly detected")
            print(f"\n❌ [SDK] BLOCKED — {reason}")
            self._update_reputation(-5)
            return {"status": "BLOCKED", "reason": reason, "score": score}

        if verdict == "QUARANTINE":
            reason = oracle_data.get("debug", {}).get("reason", "Flagged for review")
            print(f"\n⚠️  [SDK] QUARANTINE — {reason}")
            return {
                "status":     "QUARANTINE",
                "reason":     reason,
                "review_url": "https://ageniz-backend.onrender.com/quarantine",
                "score":      score
            }

        if verdict != "SAFE":
            return {"status": "ERROR", "reason": f"Unknown verdict: {verdict}"}

        signature_b64  = oracle_data.get("signature_b64")
        nonce          = oracle_data.get("nonce")

        if not signature_b64:
            return {"status": "ERROR", "reason": "Oracle did not return signature"}
        if nonce is None:
            return {"status": "ERROR", "reason": "Oracle did not return nonce"}

        signature_bytes = base64.b64decode(signature_b64)

        if len(signature_bytes) != 64:
            return {
                "status": "ERROR",
                "reason": f"Invalid signature length: {len(signature_bytes)} (expected 64)"
            }

        print(f"\n✅ [SDK] SAFE — submitting to Algorand...")
        print(f"   Nonce : {nonce}")

        sp          = self.algod_client.suggested_params()
        sp.flat_fee = True
        sp.fee      = 2000  # Base fee

        fee_tier = self.get_fee_tier()
        print(f"\n💰 [SDK] Fee Breakdown:")
        print(f"   Payment to vendor : {amount_algo:.4f} ALGO (Agent pays directly)")
        print(f"   Ageniz Fee        : 0.0500 ALGO (Flat x402 Security Fee)")
        print(f"   Total agent cost  : {amount_algo + 0.05:.4f} ALGO")

        method = Method.from_signature(
            "execute_payment(uint64,address,uint64,byte[64],address)void"
        )

        atc = AtomicTransactionComposer()

        # ── Txn 0: Smart contract verification call ──
        atc.add_method_call(
            app_id=self.app_id,
            method=method,
            sender=self.address,
            sp=sp,
            signer=self.signer,
            method_args=[
                amount_micro,      
                recipient,         
                nonce,             
                signature_bytes,   
                self.address       
            ]
        )

        # ── Txn 1: Agent pays Vendor directly (Non-Custodial) ──
        print(f"💸 [SDK] Bundling direct payment to vendor...")
        vendor_txn = PaymentTxn(
            sender=self.address,
            sp=sp,
            receiver=recipient,  
            amt=amount_micro                 
        )
        atc.add_transaction(
            TransactionWithSigner(txn=vendor_txn, signer=self.signer)
        )

        # ── Txn 2: 0.05 ALGO flat fee to Ageniz treasury ──
        print(f"💰 [SDK] Bundling 0.05 ALGO x402 fee to Ageniz treasury...")
        fee_txn = PaymentTxn(
            sender=self.address,
            sp=sp,
            receiver=AGENIZ_TREASURY,  
            amt=50_000                 
        )
        atc.add_transaction(
            TransactionWithSigner(txn=fee_txn, signer=self.signer)
        )

        try:
            result = atc.execute(self.algod_client, 4)
            tx_id  = result.tx_ids[0]

            self._tx_count      += 1
            self._last_tx_time  = time.time()
            self._update_reputation(+1)

            print(f"\n💸 [SDK] Payment confirmed!")
            print(f"   TxID      : {tx_id}")
            print(f"   Explorer  : https://testnet.explorer.perawallet.app/tx/{tx_id}")
            print(f"   Rep Score : {self.reputation_score}")
            print(f"   Fee Tier  : {fee_tier['tier']}")

            return {
                "status":     "SUCCESS",
                "tx_id":      tx_id,
                "explorer":   f"https://testnet.explorer.perawallet.app/tx/{tx_id}",
                "score":      score,
                "reputation": self.reputation_score,
                "fee_tier":   fee_tier,
                "debug":      oracle_data.get("debug", {})  # 🚨 THE UI FIX
            }

        except Exception as e:
            print(f"\n❌ [SDK] Blockchain rejected: {e}")
            return {"status": "ERROR", "reason": str(e)}

    def _get_velocity(self) -> int:
        elapsed_hours = (time.time() - self._session_start) / 3600
        if elapsed_hours < 0.01:
            return 1
        return min(100, int(self._tx_count / max(elapsed_hours, 0.01)))

    def _get_timing_delta(self) -> float:
        if self._last_tx_time is None:
            return 720.0
        return min(1800.0, time.time() - self._last_tx_time)

    def _update_reputation(self, delta: int):
        self.reputation_score = max(0, min(100, self.reputation_score + delta))

    def get_fee_tier(self) -> dict:
        score = self.reputation_score
        if score >= 85:
            return {"tier": "HIGH",   "fee_pct": 1,  "daily_limit_algo": 1000}
        elif score >= 60:
            return {"tier": "MEDIUM", "fee_pct": 3,  "daily_limit_algo": 200}
        else:
            return {"tier": "LOW",    "fee_pct": 5,  "daily_limit_algo": 50}

    def get_status(self) -> dict:
        return {
            "address":          self.address,
            "reputation_score": self.reputation_score,
            "fee_tier":         self.get_fee_tier(),
            "tx_count":         self._tx_count,
            "velocity":         self._get_velocity(),
            "timing_delta":     self._get_timing_delta()
        }