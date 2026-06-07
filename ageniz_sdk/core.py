"""
Ageniz SDK — v2.5.0
Zero-trust ML Risk Oracle and Firewall for Algorand AI Agents

Architecture (FIREWALL MODEL — no custody):
- Agent calls pay() for every payment
- Oracle scores the transaction via ML + heuristics + Ed25519 sign
- If SAFE, agent submits a 3-txn atomic group:
    Txn 0: execute_payment() ABI call  — contract VERIFIES oracle sig + checks caps
    Txn 1: Agent → Vendor              — agent pays vendor directly (no custody)
    Txn 2: Agent → Ageniz treasury     — 0.05 ALGO flat security fee

Shadow Mode (observe()):
- Agent calls observe() instead of pay()
- Oracle runs all 4 layers identically — heuristics, ML, caps, verdict
- Payment ALWAYS goes through regardless of verdict (simple PaymentTxn, no atomic group)
- Everything logged to shadow_logs table with ageniz_verdict for training data
- Developer can later add human_verdict via PATCH /shadow/{id}/verdict
- Use this to collect real-world labelled data before enforcing the firewall

Fee Strategy:
  pay() Txn 0 (ABI call) : fee = 3000 µA
    → 2000 µA above minimum → grants +1400 opcode budget to the group
    → Total opcode budget = 2100 (base 700×3) + 1400 (extra) = 3500
    → ed25519verify_bare costs 1900 — comfortably covered, no ensure_budget needed
  pay() Txn 1 (Vendor)   : fee = 1000 µA  (standard)
  pay() Txn 2 (Fee)      : fee = 1000 µA  (standard)
  Total network fee pay(): 5000 µA = 0.005 ALGO

  observe() Txn 0 (Vendor only): fee = 1000 µA (standard — no ABI call, no treasury fee)

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
GROUP_SIZE            = 3        # Always exactly 3 txns in pay() mode


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

        print(f"✅ AgenizSDK v2.4.0 initialized  [Firewall Model — No Custody]")
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
    # pay  — LIVE FIREWALL mode
    # ─────────────────────────────────────────────────────────────────
    def pay(
        self,
        recipient:   str,
        amount_algo: float,
        context:     str = ""
    ) -> dict:
        """
        LIVE FIREWALL mode. Payment blocked if Oracle returns anything other than SAFE.

        Builds a 3-txn atomic group ONLY if Oracle returns SAFE:
          Txn 0 — execute_payment() ABI call (contract verifies sig + updates caps)
          Txn 1 — PaymentTxn: agent → vendor  (actual transfer, no contract custody)
          Txn 2 — PaymentTxn: agent → Ageniz treasury (0.05 ALGO flat fee)

        Returns dict with status: SUCCESS | BLOCKED | QUARANTINE | ERROR
        """
        amount_micro = int(amount_algo * 1_000_000)

        print(f"\n{'='*55}")
        print(f"🤖 [SDK] Payment Request  [LIVE MODE]")
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

        verdict      = oracle_data.get("verdict")
        score        = oracle_data.get("confidence_score")
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
                "reason": f"Invalid signature length: {len(signature_bytes)} (expected 64)",
                "debug":  oracle_debug
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
        sp_abi.fee      = 5000
        # ── Fee setup ──────────────────────────────────────────────────
       
        
        sp_pay = self.algod_client.suggested_params()
        sp_pay.flat_fee = True
        sp_pay.fee      = PAY_TXN_FEE_MICRO

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

        # ── Txn 0: ABI verification call ──────────────────────────────\
        #contract checks: group_size==3, verifies oracle sig,
        # checks daily cap, updates state. Pure verifier — no inner txns.
        atc.add_method_call(
            app_id      = self.app_id,
            method      = method,
            sender      = self.address,
            sp          = sp_abi,
            signer      = self.signer,
            method_args = [
                amount_micro,
                recipient,
                nonce,
                signature_bytes,
                self.address
            ],
            accounts    = [recipient]
        )

        # ── Txn 1: Agent → Vendor ──────────────────────────────────────
        # Contract asserts at gtxn[1]:
        #   sender   == Txn.sender  (agent)
        #   receiver == recipient   (vendor)
        vendor_txn = PaymentTxn(
            sender   = self.address,
            sp       = sp_pay,
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
        print(f"💰 [SDK] Bundling 0.05 ALGO security fee to Ageniz treasury...")
        fee_txn = PaymentTxn(
            sender   = self.address,
            sp       = sp_pay,
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
    # observe  — SHADOW mode
    # ─────────────────────────────────────────────────────────────────
    def observe(
        self,
        recipient:    str,
        amount_algo:  float,
        context:      str = "",
        scenario_tag: str | None = None
    ) -> dict:
        """
        SHADOW MODE. Payment always goes through regardless of Oracle verdict.

        Oracle still runs all 4 layers identically to pay() — heuristics,
        ML scoring, spend caps — and returns a full verdict. But no atomic
        group is built. A simple PaymentTxn executes directly.

        Everything is logged to shadow_logs table in Supabase with:
          - ageniz_verdict: what Ageniz WOULD have decided
          - human_verdict: null initially, operator fills in later via API
          - mode: 'shadow'

        Use this to:
          1. Collect real-world labelled training data without blocking traffic
          2. Validate Ageniz accuracy against human ground truth
          3. Onboard new agents in observe mode before switching to pay()

        Returns dict with:
          status:          EXECUTED (always — payment went through)
          ageniz_verdict:  SAFE | QUARANTINE | BLOCKED (what Ageniz would have done)
          would_have_blocked: bool
          shadow_log_id:   UUID for submitting human verdict later
          tx_id:           on-chain transaction ID
        """
        amount_micro = int(amount_algo * 1_000_000)

        print(f"\n{'='*55}")
        print(f"👁️  [SDK] Payment Request  [SHADOW MODE]")
        print(f"   Recipient : {recipient}")
        print(f"   Amount    : {amount_algo} ALGO  ({amount_micro} µALGO)")
        print(f"   NOTE: Payment will execute regardless of verdict")
        print(f"{'='*55}")

        # ── Step 1: Oracle shadow attestation ──────────────────────────
        # Hits /shadow/attest — same ML/heuristics, no signature issued
        print(f"\n👁️  [SDK → Oracle] Requesting shadow ML scoring...")

        try:
            oracle_res  = requests.post(
                f"{self.oracle_url}/shadow/attest",
                json={
                    "agent_address":     self.address,
                    "recipient_address": recipient,
                    "amount_micro":      amount_micro,
                    "api_key":           self.api_key,
                    "scenario_tag":      scenario_tag,
                },
                timeout=15
            )
            oracle_data = oracle_res.json()
        except Exception as e:
            print(f"❌ [SDK] Oracle unreachable: {e}")
            return {"status": "ERROR", "reason": str(e)}

        ageniz_verdict = oracle_data.get("verdict", "UNKNOWN")
        score          = oracle_data.get("confidence_score")
        oracle_debug   = oracle_data.get("debug") or {}
        shadow_log_id  = oracle_data.get("shadow_log_id")  # UUID for human verdict later

        would_have_blocked = ageniz_verdict in ("QUARANTINE", "BLOCKED", "ANOMALY", "INVALID")

        print(f"   Ageniz Verdict   : {ageniz_verdict}  {'⚠️  (would have blocked)' if would_have_blocked else '✅ (would have passed)'}")
        print(f"   Confidence Score : {score}")
        print(f"   Shadow Log ID    : {shadow_log_id}")
        print(f"   Debug            : {oracle_debug}")

        # ── Step 2: Execute payment regardless ────────────────────────
        # Simple PaymentTxn — no atomic group, no ABI call, no treasury fee
        # Shadow mode is cheaper: only 1000 µA network fee
        print(f"\n💸 [SDK] Executing payment (shadow mode — no firewall enforcement)...")

        sp = self.algod_client.suggested_params()
        sp.flat_fee = True
        sp.fee      = PAY_TXN_FEE_MICRO

        try:
            txn    = PaymentTxn(
                sender   = self.address,
                sp       = sp,
                receiver = recipient,
                amt      = amount_micro
            )
            signed = txn.sign(self.private_key)
            tx_id  = self.algod_client.send_transaction(signed)

            # Wait for confirmation
            from algosdk.v2client.algod import AlgodClient
            from algosdk import transaction as algo_txn
            algo_txn.wait_for_confirmation(self.algod_client, tx_id, 4)

            self._tx_count    += 1
            self._last_tx_time = time.time()

            print(f"\n💸 [SDK] Payment executed!")
            print(f"   TxID           : {tx_id}")
            print(f"   Ageniz Verdict : {ageniz_verdict}  {'⚠️  WOULD HAVE BLOCKED' if would_have_blocked else '✅ would have passed'}")
            print(f"   Explorer       : https://testnet.explorer.perawallet.app/tx/{tx_id}")

            # Notify oracle of actual txn_id so shadow log is complete
            if shadow_log_id:
                try:
                    requests.patch(
                        f"{self.oracle_url}/shadow/{shadow_log_id}/txn",
                        json={"algo_txn_id": tx_id},
                        timeout=5
                    )
                except Exception:
                    pass  # non-fatal

            return {
                "status":             "EXECUTED",
                "ageniz_verdict":     ageniz_verdict,
                "would_have_blocked": would_have_blocked,
                "shadow_log_id":      shadow_log_id,
                "tx_id":              tx_id,
                "explorer":           f"https://testnet.explorer.perawallet.app/tx/{tx_id}",
                "score":              score,
                "debug":              oracle_debug
            }

        except Exception as e:
            print(f"\n❌ [SDK] Payment failed: {e}")
            return {
                "status":             "ERROR",
                "ageniz_verdict":     ageniz_verdict,
                "would_have_blocked": would_have_blocked,
                "shadow_log_id":      shadow_log_id,
                "reason":             str(e),
                "debug":              oracle_debug
            }

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