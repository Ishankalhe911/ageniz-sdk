"""
Ageniz SDK — v2.0
Matches ARC56 exactly:
  execute_payment(uint64, address, uint64, byte[64], address)void
Payload: b"MX" + agent(32) + recipient(32) + amount(8) + nonce(8) + b"SAFE" = 86 bytes

Security fixes in v2:
- V1: Recipient bound to signature (bait-and-switch prevention)
- V2: Nonce from Oracle (replay attack prevention)
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
ORACLE_URL       = os.getenv("ORACLE_URL", "https://ageniz-oracle.onrender.com")
APP_ID           = int(os.getenv("APP_ID", 0))
AGENIZ_TREASURY  = "EUKRBWJBKMYRCRQOHFGEUMXGK2JDXESZ5A2W5SJVJVTF7BW5CWBSUG422Q"


class AgenizSDK:
    def __init__(
        self,
        wallet_mnemonic:  str,
        ageniz_api_key:   str   = "test_key",
        app_id:           int   = APP_ID,
        oracle_url:       str   = ORACLE_URL,
        daily_cap_algo:   float = 5.0
    ):
        # Wallet stays local — never sent to Oracle
        self.private_key    = mnemonic.to_private_key(wallet_mnemonic)
        self.address        = account.address_from_private_key(self.private_key)
        self.signer         = AccountTransactionSigner(self.private_key)

        self.api_key        = ageniz_api_key
        self.app_id         = app_id
        self.oracle_url     = oracle_url
        self.daily_cap_algo = daily_cap_algo
        self.algod_client   = algod.AlgodClient("", ALGOD_URL)

        # Velocity tracking
        self._tx_count      = 0
        self._last_tx_time  = None
        self._session_start = time.time()

        # Reputation (in-memory)
        self.reputation_score = 0

        print(f"✅ AgenizSDK v2.0 initialized")
        print(f"   Agent Address : {self.address}")
        print(f"   App ID        : {self.app_id}")
        print(f"   Oracle        : {self.oracle_url}")
        print(f"   Treasury      : {AGENIZ_TREASURY}")

    def opt_in(self) -> bool:
        """Opts the agent's wallet into the Ageniz Smart Contract."""
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
        """
        Main method. Developer calls this for every payment.
        Returns: SUCCESS / BLOCKED / QUARANTINE / ERROR
        """
        amount_micro = int(amount_algo * 1_000_000)

        print(f"\n{'='*50}")
        print(f"🤖 [SDK] Payment Request")
        print(f"   Recipient : {recipient}")
        print(f"   Amount    : {amount_algo} ALGO ({amount_micro} microALGO)")
        print(f"{'='*50}")

        # ── Step 1: Call Oracle ────────────────────────────────────────
        print(f"\n🛡️  [SDK → Oracle] Requesting ML attestation...")

        try:
            oracle_res  = requests.post(
                f"{self.oracle_url}/attest",
                json={
                    "agent_address":     self.address,
                    "recipient_address": recipient,
                    "amount_micro":      amount_micro,
                    "velocity":          self._get_velocity(),
                    "timing_delta":      self._get_timing_delta(),
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

        # ── Step 2: Route based on verdict ────────────────────────────
        if verdict in ("BLOCKED", "ANOMALY", "INVALID"):
            reason = oracle_data.get("debug", {}).get("reason", "Anomaly detected")
            print(f"\n❌ [SDK] BLOCKED — {reason}")
            self._update_reputation(-5)
            return {"status": "BLOCKED", "reason": reason, "score": score}

        if verdict == "QUARANTINE":
            print(f"\n⚠️  [SDK] QUARANTINE — awaiting manual approval")
            return {
                "status":     "QUARANTINE",
                "review_url": "https://ageniz-web3-firewall.vercel.app",
                "score":      score
            }

        if verdict != "SAFE":
            return {"status": "ERROR", "reason": f"Unknown verdict: {verdict}"}

        # ── Step 3: Extract signature + nonce from Oracle response ─────
        signature_b64  = oracle_data.get("signature_b64")
        nonce          = oracle_data.get("nonce")  # ← Oracle-generated nonce

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

        # ── Step 4: SAFE — submit to Algorand ─────────────────────────
        print(f"\n✅ [SDK] SAFE — submitting to Algorand...")
        print(f"   Nonce : {nonce}")

        sp          = self.algod_client.suggested_params()
        sp.flat_fee = True
        sp.fee      = 6000  # covers inner txn + fee txn

        # Fee display
        fee_tier   = self.get_fee_tier()
        fee_micro  = int(amount_micro * fee_tier["fee_pct"] / 100)
        net_micro  = amount_micro - fee_micro
       # Fee display (Updated for Reality)
        print(f"\n💰 [SDK] Fee Breakdown:")
        print(f"   Gross Amount : {amount_micro/1e6:.4f} ALGO")
        print(f"   Ageniz Fee   : 0.0500 ALGO (Flat x402 Security Fee)")
        print(f"   Net to Recip : {(amount_micro - 50000)/1e6:.4f} ALGO")

        # ABI method — matches ARC56 exactly
        # execute_payment(uint64, address, uint64, byte[64], address)void
        # args:           amount  recipient nonce   signature  agent
        method = Method.from_signature(
            "execute_payment(uint64,address,uint64,byte[64],address)void"
        )

        atc = AtomicTransactionComposer()

        atc = AtomicTransactionComposer()

        # Txn 0: Smart contract call
        atc.add_method_call(
            app_id=self.app_id,
            method=method,
            sender=self.address,
            sp=sp,
            signer=self.signer,
            method_args=[
                amount_micro,      # uint64  — amount
                recipient,         # address — recipient
                nonce,             # uint64  — one-time nonce
                signature_bytes,   # byte[64] — Oracle signature
                self.address       # address — agent
            ]
        )

        # 🚨 Txn 1: THE VENDOR PAYMENT (The part that got deleted!) 🚨
        print(f"💸 [SDK] Bundling payment to vendor...")
        vendor_txn = PaymentTxn(
            sender=self.address,
            sp=sp,
            receiver=recipient,    
            amt=amount_micro       
        )
        atc.add_transaction(
            TransactionWithSigner(txn=vendor_txn, signer=self.signer)
        )

        # 💰 Txn 2: THE TREASURY FEE
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

            self._tx_count     += 1
            self._last_tx_time  = time.time()
            self._update_reputation(+1)

            print(f"\n💸 [SDK] Payment confirmed!")
            print(f"   TxID      : {tx_id}")
            print(f"   Explorer  : https://testnet.explorer.perawallet.app/tx/{tx_id}")
            print(f"   Rep Score : {self.reputation_score}")
            print(f"   Fee Tier  : {fee_tier['tier']} ({fee_tier['fee_pct']}%)")

            return {
                "status":     "SUCCESS",
                "tx_id":      tx_id,
                "explorer":   f"https://testnet.explorer.perawallet.app/tx/{tx_id}",
                "score":      score,
                "reputation": self.reputation_score,
                "fee_tier":   fee_tier
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