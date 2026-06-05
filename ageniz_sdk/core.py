"""
Ageniz SDK — v2.3.0
Zero-trust ML Risk Oracle and Firewall for Algorand AI Agents

Architecture (FIREWALL MODEL — no custody):
- Agent calls pay() for every payment
- Oracle scores the transaction via ML + heuristics + Ed25519 sign
- If SAFE, agent submits a 3-txn atomic group:
    Txn 0: execute_payment() ABI call  — contract VERIFIES oracle sig + checks caps
    Txn 1: Agent → Vendor              — agent pays vendor directly (no custody)
    Txn 2: Agent → Ageniz treasury     — 0.05 ALGO flat security fee

Fee Strategy:
  Txn 0 (ABI call) : fee = 3000 µA
    → 2000 µA above minimum → grants +1400 opcode budget to the group
    → Total opcode budget = 2100 (base 700×3) + 1400 (extra) = 3500
    → ed25519verify_bare costs 1900 — comfortably covered, no ensure_budget needed
  Txn 1 (Vendor)   : fee = 1000 µA  (standard)
  Txn 2 (Fee)      : fee = 1000 µA  (standard)
  Total network fee : 5000 µA = 0.005 ALGO

Security Fixes:
  V1: Recipient bound to Ed25519 signature (bait-and-switch prevention)
  V2: Nonce from Oracle (replay attack prevention)
  V3: Server-side velocity/timing (SDK spoofing prevention)
  V4: Group size 3 enforced on-chain — contract cannot be bypassed without all 3 txns
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

ALGOD_URL       = "https://testnet-api.algonode.cloud"
ORACLE_URL      = os.getenv("ORACLE_URL", "https://ageniz-backend.onrender.com")
APP_ID          = int(os.getenv("APP_ID", 0))
AGENIZ_TREASURY = "EUKRBWJBKMYRCRQOHFGEUMXGK2JDXESZ5A2W5SJVJVTF7BW5CWBSUG422Q"

# Fee constants
AGENIZ_FLAT_FEE_MICRO = 50_000   # 0.05 ALGO flat security fee
ABI_TXN_FEE_MICRO     = 3_000    # Txn 0: higher fee → extra opcode budget for ed25519verify_bare
PAY_TXN_FEE_MICRO     = 1_000    # Txn 1 + Txn 2: standard minimum
GROUP_SIZE            = 3        # Always exactly 3 txns


class AgenizSDK:
    def __init__(
        self,
        wallet_mnemonic: str,
        ageniz_api_key:  str   = "test_key",
        app_id:          int   = APP_ID,
        oracle_url:      str   = ORACLE_URL,
        daily_cap_algo:  float = 50.0
    ):
        # Wallet stays local — private key never sent to Oracle
        self.private_key    = mnemonic.to_private_key(wallet_mnemonic)
        self.address        = account.address_from_private_key(self.private_key)
        self.signer         = AccountTransactionSigner(self.private_key)

        self.api_key        = ageniz_api_key
        self.app_id         = app_id
        self.oracle_url     = oracle_url
        self.daily_cap_algo = daily_cap_algo
        self.algod_client   = algod.AlgodClient("", ALGOD_URL)

        # Session tracking (local only — for UI/dashboard display)
        self._tx_count      = 0
        self._last_tx_time  = None
        self._session_start = time.time()

        # In-memory reputation score
        self.reputation_score = 0

        print(f"✅ AgenizSDK v3.0.0 initialized  [Firewall Model — No Custody]")
        print(f"   Agent Address : {self.address}")
        print(f"   App ID        : {self.app_id}")
        print(f"   Oracle        : {self.oracle_url}")
        print(f"   Treasury      : {AGENIZ_TREASURY}")
        print(f"   Group Size    : {GROUP_SIZE}  (ABI call | Vendor pay | Ageniz fee)")

    # ─────────────────────────────────────────────────────────────────
    # opt_in
    # ─────────────────────────────────────────────────────────────────
    def opt_in(self) -> bool:
        """Opts the agent's wallet into the Ageniz Smart Contract."""
        print(f"\n🔌 [SDK] Opting in to App ID: {self.app_id}...")

        sp = self.algod_client.suggested_params()
        sp.flat_fee = True
        sp.fee      = PAY_TXN_FEE_MICRO  # single txn, standard fee

        atc = AtomicTransactionComposer()
        atc.add_method_call(
            app_id      = self.app_id,
            method      = Method.from_signature("opt_in()void"),
            sender      = self.address,
            sp          = sp,
            signer      = self.signer,
            method_args = [],
            on_complete = OnComplete.OptInOC
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

    # ─────────────────────────────────────────────────────────────────
    # pay  — main entry point
    # ─────────────────────────────────────────────────────────────────
    def pay(
        self,
        recipient:   str,
        amount_algo: float,
        context:     str = ""
    ) -> dict:
        """
        Main method. Developer calls this for every payment.

        Builds a 3-txn atomic group ONLY if Oracle returns SAFE:
          Txn 0 — execute_payment() ABI call (contract verifies sig + updates caps)
          Txn 1 — PaymentTxn: agent → vendor  (actual transfer, no contract custody)
          Txn 2 — PaymentTxn: agent → Ageniz treasury (0.05 ALGO flat fee)

        Returns dict with status: SUCCESS | BLOCKED | QUARANTINE | ERROR
        """
        amount_micro = int(amount_algo * 1_000_000)

        print(f"\n{'='*55}")
        print(f"🤖 [SDK] Payment Request")
        print(f"   Recipient : {recipient}")
        print(f"   Amount    : {amount_algo} ALGO  ({amount_micro} µALGO)")
        print(f"{'='*55}")

        # ── Step 1: Oracle attestation ─────────────────────────────────
        print(f"\n🛡️  [SDK → Oracle] Requesting ML attestation...")

        try:
            # Velocity + timing_delta intentionally NOT sent here.
            # Oracle computes them server-side from Supabase to prevent SDK spoofing.
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

        verdict     = oracle_data.get("verdict")
        score       = oracle_data.get("confidence_score")
        # FIX: forward oracle debug payload so agent.py can read
        # wallet_tier, layer_hit, reason, vendor_name, etc.
        oracle_debug = oracle_data.get("debug") or {}

        print(f"   Verdict          : {verdict}")
        print(f"   Confidence Score : {score}")
        print(f"   Debug            : {oracle_debug}")

        # ── Step 2: Route on verdict ───────────────────────────────────
        if verdict in ("BLOCKED", "ANOMALY", "INVALID"):
            reason = oracle_debug.get("reason", "Anomaly detected")
            print(f"\n❌ [SDK] BLOCKED — {reason}")
            self._update_reputation(-5)
            return {
                "status": "BLOCKED",
                "reason": reason,
                "score":  score,
                "debug":  oracle_debug
            }

        if verdict == "QUARANTINE":
            reason = oracle_debug.get("reason", "Flagged for review")
            print(f"\n⚠️  [SDK] QUARANTINE — {reason}")
            return {
                "status":     "QUARANTINE",
                "reason":     reason,
                "review_url": f"{self.oracle_url}/quarantine",
                "score":      score,
                "debug":      oracle_debug
            }

        if verdict != "SAFE":
            return {
                "status": "ERROR",
                "reason": f"Unknown verdict: {verdict}",
                "debug":  oracle_debug
            }

        # ── Step 3: Unpack Oracle signature + nonce ────────────────────
        signature_b64 = oracle_data.get("signature_b64")
        nonce         = oracle_data.get("nonce")

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

        # ── Step 4: Build 3-txn atomic group ──────────────────────────
        print(f"\n✅ [SDK] SAFE — building 3-txn atomic group...")
        print(f"   Nonce : {nonce}")

        # ── Fee setup ──────────────────────────────────────────────────
        # Txn 0 (ABI call): fee = 3000 µA
        #   Extra 2000 µA above minimum → AVM grants +1400 opcode budget
        #   Group base budget  = 700 × 3 = 2100
        #   Extra budget       = (3000 - 1000) / 1000 × 700 = 1400
        #   Total              = 3500 — covers ed25519verify_bare (1900) + all ops
        #
        # Txn 1 + Txn 2 (PaymentTxns): fee = 1000 µA each (standard)
        sp_abi = self.algod_client.suggested_params()
        sp_abi.flat_fee = True
        sp_abi.fee      = 5000  # 3000 µA

        sp_pay = self.algod_client.suggested_params()
        sp_pay.flat_fee = True
        sp_pay.fee      = PAY_TXN_FEE_MICRO  # 1000 µA

        total_network_fee = ABI_TXN_FEE_MICRO + PAY_TXN_FEE_MICRO + PAY_TXN_FEE_MICRO

        print(f"\n💰 [SDK] Fee Breakdown:")
        print(f"   Gross Payment  : {amount_micro / 1e6:.6f} ALGO  → Vendor")
        print(f"   Ageniz Fee     : {AGENIZ_FLAT_FEE_MICRO / 1e6:.4f} ALGO  → Treasury")
        print(f"   Network Fees   : {total_network_fee / 1e6:.4f} ALGO  (3000 + 1000 + 1000 µA)")

        # ABI method signature — must match Puya contract exactly
        method = Method.from_signature(
            "execute_payment(uint64,address,uint64,byte[64],address)void"
        )

        atc = AtomicTransactionComposer()

        # ── Txn 0: ABI verification call ──────────────────────────────
        # Contract checks: group_size==3, verifies oracle sig,
        # checks daily cap, updates state. Pure verifier — no inner txns.
        atc.add_method_call(
            app_id      = self.app_id,
            method      = method,
            sender      = self.address,
            sp          = sp_abi,          # 3000 µA — grants extra opcode budget
            signer      = self.signer,
            method_args = [
                amount_micro,     # uint64   — amount in µALGO
                recipient,        # address  — vendor wallet
                nonce,            # uint64   — monotonic one-time nonce
                signature_bytes,  # byte[64] — Oracle Ed25519 signature
                self.address      # address  — agent (must match Txn.sender)
            ],
            accounts    = [recipient]      # allows contract to read vendor account
        )

        # ── Txn 1: Agent → Vendor ──────────────────────────────────────
        # Contract asserts at gtxn[1]:
        #   sender   == Txn.sender  (agent)
        #   receiver == recipient   (vendor)
        #   amount   == amount      (µALGO)
        vendor_txn = PaymentTxn(
            sender   = self.address,
            sp       = sp_pay,             # 1000 µA
            receiver = recipient,
            amt      = amount_micro
        )
        atc.add_transaction(
            TransactionWithSigner(txn=vendor_txn, signer=self.signer)
        )

        # ── Txn 2: Agent → Ageniz treasury ────────────────────────────
        # Contract asserts at gtxn[2]:
        #   receiver == Global.creator_address
        #   amount   == 50_000
        #   sender   == Txn.sender
        print(f"💰 [SDK] Bundling 0.05 ALGO security fee to Ageniz treasury...")
        fee_txn = PaymentTxn(
            sender   = self.address,
            sp       = sp_pay,             # 1000 µA
            receiver = AGENIZ_TREASURY,
            amt      = AGENIZ_FLAT_FEE_MICRO
        )
        atc.add_transaction(
            TransactionWithSigner(txn=fee_txn, signer=self.signer)
        )

        # ── Step 5: Submit ─────────────────────────────────────────────
        try:
            result = atc.execute(self.algod_client, 4)
            tx_id  = result.tx_ids[0]

            self._tx_count    += 1
            self._last_tx_time = time.time()
            self._update_reputation(+1)

            fee_tier = self.get_fee_tier()

            print(f"\n💸 [SDK] Payment confirmed!")
            print(f"   TxID      : {tx_id}")
            print(f"   Explorer  : https://testnet.explorer.perawallet.app/tx/{tx_id}")
            print(f"   Rep Score : {self.reputation_score}")
            print(f"   Fee Tier  : {fee_tier['tier']}  ({fee_tier['fee_pct']}%)")

            return {
                "status":     "SUCCESS",
                "tx_id":      tx_id,
                "explorer":   f"https://testnet.explorer.perawallet.app/tx/{tx_id}",
                "score":      score,
                "reputation": self.reputation_score,
                "fee_tier":   fee_tier,
                "debug":      oracle_debug
            }

        except Exception as e:
            print(f"\n❌ [SDK] Blockchain rejected: {e}")
            return {"status": "ERROR", "reason": str(e), "debug": oracle_debug}

    # ─────────────────────────────────────────────────────────────────
    # UI & Dashboard helpers  (local only, server-side is authoritative)
    # ─────────────────────────────────────────────────────────────────
    def _get_velocity(self) -> int:
        elapsed_hours = (time.time() - self._session_start) / 3600
        if elapsed_hours < 0.01:
            return 1
        return min(100, int(self._tx_count / max(elapsed_hours, 0.01)))

    def _get_timing_delta(self) -> float:
        if self._last_tx_time is None:
            return 720.0
        return min(1800.0, time.time() - self._last_tx_time)

    def _update_reputation(self, delta: int) -> None:
        self.reputation_score = max(0, min(100, self.reputation_score + delta))

    def get_fee_tier(self) -> dict:
        score = self.reputation_score
        if score >= 85:
            return {"tier": "HIGH",   "fee_pct": 1, "daily_limit_algo": 1000}
        elif score >= 60:
            return {"tier": "MEDIUM", "fee_pct": 3, "daily_limit_algo": 200}
        else:
            return {"tier": "LOW",    "fee_pct": 5, "daily_limit_algo": 50}

    def get_status(self) -> dict:
        return {
            "address":          self.address,
            "reputation_score": self.reputation_score,
            "fee_tier":         self.get_fee_tier(),
            "tx_count":         self._tx_count,
            "velocity":         self._get_velocity(),
            "timing_delta":     self._get_timing_delta()
        }