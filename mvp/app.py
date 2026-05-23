#!/usr/bin/env python3
"""Minimal runnable backend for the AgentTask -> policy -> asset -> audit demo.

The implementation intentionally uses only the Python standard library so the
MVP can run in a clean environment without dependency installation.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import mimetypes
import os
import queue
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

# Optional ZKP verifier — dynamically imported so app.py keeps stdlib-only deps
_zkp_backend_dir = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "zkp", "backend")
)
if os.path.isdir(_zkp_backend_dir):
    sys.path.insert(0, _zkp_backend_dir)
    try:
        from zkp_verifier_service import ZkpVerifierService, build_zkp_verifier  # type: ignore
    except ImportError:
        ZkpVerifierService = None  # type: ignore
        def build_zkp_verifier(zkp_dir: str | None = None) -> None: return None  # type: ignore
    finally:
        sys.path.pop(0)
else:
    ZkpVerifierService = None  # type: ignore
    def build_zkp_verifier(zkp_dir: str | None = None) -> None: return None  # type: ignore


DEFAULT_DB = os.path.join(os.path.dirname(__file__), "demo.db")
STATIC_ROOT = os.path.join(os.path.dirname(__file__), "static")


def now_ms() -> int:
    return int(time.time() * 1000)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def parse_json_body(handler: http.server.BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON body: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("JSON body must be an object")
    return data


class Store:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS institutions (
              institution_id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              did TEXT UNIQUE,
              status TEXT NOT NULL,
              role TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
              user_id TEXT PRIMARY KEY,
              institution_id TEXT,
              display_name TEXT NOT NULL,
              address TEXT UNIQUE NOT NULL,
              role TEXT NOT NULL,
              status TEXT NOT NULL,
              kyc_status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(institution_id) REFERENCES institutions(institution_id)
            );

            CREATE TABLE IF NOT EXISTS licensed_institutions (
              institution_id TEXT PRIMARY KEY,
              license_type TEXT NOT NULL,
              license_number TEXT NOT NULL,
              jurisdiction TEXT NOT NULL,
              regulator TEXT NOT NULL,
              status TEXT NOT NULL,
              permitted_activities_json TEXT NOT NULL,
              valid_until TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(institution_id) REFERENCES institutions(institution_id)
            );

            CREATE TABLE IF NOT EXISTS kyc_aml_profiles (
              subject TEXT PRIMARY KEY,
              subject_type TEXT NOT NULL,
              kyc_status TEXT NOT NULL,
              aml_status TEXT NOT NULL,
              risk_rating TEXT NOT NULL,
              professional_investor INTEGER NOT NULL DEFAULT 0,
              sanctions_checked_at TEXT NOT NULL,
              source TEXT NOT NULL,
              evidence_hash TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS legal_documents (
              document_id TEXT PRIMARY KEY,
              title TEXT NOT NULL,
              document_type TEXT NOT NULL,
              content_hash TEXT UNIQUE NOT NULL,
              storage_uri TEXT NOT NULL,
              jurisdiction TEXT NOT NULL,
              status TEXT NOT NULL,
              effective_at TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS asset_rights_mappings (
              rights_mapping_id TEXT PRIMARY KEY,
              asset_id TEXT NOT NULL,
              asset_type TEXT NOT NULL,
              rights_type TEXT NOT NULL,
              document_id TEXT NOT NULL,
              rights_summary TEXT NOT NULL,
              redemption_terms TEXT NOT NULL,
              transfer_restrictions_json TEXT NOT NULL,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(document_id) REFERENCES legal_documents(document_id)
            );

            CREATE TABLE IF NOT EXISTS custody_wallets (
              wallet_id TEXT PRIMARY KEY,
              owner TEXT NOT NULL,
              owner_type TEXT NOT NULL,
              wallet_address TEXT UNIQUE NOT NULL,
              kms_key_ref TEXT NOT NULL,
              custody_provider TEXT NOT NULL,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS signature_requests (
              signature_request_id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              wallet_id TEXT NOT NULL,
              signer TEXT NOT NULL,
              payload_hash TEXT NOT NULL,
              signature_hash TEXT NOT NULL,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(task_id) REFERENCES agent_tasks(task_id),
              FOREIGN KEY(wallet_id) REFERENCES custody_wallets(wallet_id)
            );

            CREATE TABLE IF NOT EXISTS oracle_attestations (
              attestation_id TEXT PRIMARY KEY,
              source TEXT NOT NULL,
              source_ref TEXT NOT NULL,
              subject_id TEXT NOT NULL,
              period TEXT NOT NULL,
              content_hash TEXT NOT NULL,
              value_json TEXT NOT NULL,
              status TEXT NOT NULL,
              observed_at TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_tasks (
              task_id TEXT PRIMARY KEY,
              requester TEXT NOT NULL,
              requester_type TEXT NOT NULL,
              requester_signature TEXT,
              intent TEXT NOT NULL,
              intent_hash TEXT NOT NULL,
              constraints_json TEXT NOT NULL,
              authorization_scope_json TEXT NOT NULL,
              assigned_agent TEXT NOT NULL,
              plan_hash TEXT,
              policy_result TEXT,
              execution_status TEXT NOT NULL,
              related_tx_hashes_json TEXT NOT NULL DEFAULT '[]',
              evidence_hash TEXT,
              idempotency_key TEXT NOT NULL,
              risk_preference TEXT,
              estimated_risk_level TEXT,
              error_code TEXT,
              error_message TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE (requester, idempotency_key)
            );

            CREATE TABLE IF NOT EXISTS tool_calls (
              tool_call_id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              agent_id TEXT NOT NULL,
              tool_name TEXT NOT NULL,
              input_hash TEXT NOT NULL,
              output_hash TEXT,
              risk_level TEXT NOT NULL,
              policy_result TEXT,
              result TEXT,
              error_code TEXT,
              error_message TEXT,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              FOREIGN KEY(task_id) REFERENCES agent_tasks(task_id)
            );

            CREATE TABLE IF NOT EXISTS policy_evaluations (
              policy_evaluation_id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              agent_id TEXT NOT NULL,
              tool_name TEXT,
              policy_set_version TEXT NOT NULL,
              input_hash TEXT NOT NULL,
              result TEXT NOT NULL,
              reasons_json TEXT NOT NULL,
              evaluated_at TEXT NOT NULL,
              FOREIGN KEY(task_id) REFERENCES agent_tasks(task_id)
            );

            CREATE TABLE IF NOT EXISTS assets (
              asset_id TEXT PRIMARY KEY,
              asset_type TEXT NOT NULL,
              issuer TEXT NOT NULL,
              owner TEXT NOT NULL,
              amount INTEGER NOT NULL,
              metadata_hash TEXT NOT NULL,
              status TEXT NOT NULL,
              created_by_task_id TEXT NOT NULL,
              updated_by_task_id TEXT NOT NULL,
              chain_tx_hash TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transaction_records (
              tx_hash TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              contract_name TEXT NOT NULL,
              method_name TEXT NOT NULL,
              caller TEXT NOT NULL,
              payload_hash TEXT NOT NULL,
              status TEXT NOT NULL,
              block_height INTEGER NOT NULL,
              block_hash TEXT NOT NULL,
              submitted_at TEXT NOT NULL,
              confirmed_at TEXT NOT NULL,
              FOREIGN KEY(task_id) REFERENCES agent_tasks(task_id)
            );

            CREATE TABLE IF NOT EXISTS chain_events (
              event_id TEXT PRIMARY KEY,
              tx_hash TEXT NOT NULL,
              block_height INTEGER NOT NULL,
              block_hash TEXT NOT NULL,
              event_name TEXT NOT NULL,
              agent_task_id_hash TEXT NOT NULL,
              asset_id TEXT,
              event_payload_json TEXT NOT NULL,
              observed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
              log_id TEXT PRIMARY KEY,
              operator TEXT NOT NULL,
              action TEXT NOT NULL,
              target_id TEXT NOT NULL,
              agent_task_id TEXT NOT NULL,
              agent_id TEXT NOT NULL,
              tx_hash TEXT,
              tool_call_hash TEXT,
              request_hash TEXT NOT NULL,
              result TEXT NOT NULL,
              evidence_hash TEXT NOT NULL,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(agent_task_id) REFERENCES agent_tasks(task_id)
            );

            CREATE TABLE IF NOT EXISTS task_queue (
              queue_id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              status TEXT NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0,
              last_error TEXT,
              locked_at TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(task_id) REFERENCES agent_tasks(task_id)
            );
            """
        )
        self.conn.commit()
        self.seed_identity()

    def seed_identity(self) -> None:
        now = now_iso()
        institutions = [
            ("issuer_A", "Issuer A", "did:demo:issuer-a", "active", "issuer"),
            ("regulator", "Regulator", "did:demo:regulator", "active", "regulator"),
            ("custodian_A", "Custodian A", "did:demo:custodian-a", "active", "custodian"),
        ]
        users = [
            ("user_alice", "issuer_A", "Alice", "alice", "trader", "active", "verified"),
            ("user_bob", "issuer_A", "Bob", "bob", "trader", "active", "verified"),
        ]
        licensed_institutions = [
            (
                "issuer_A",
                "demo_sfc_type_9_fund_manager",
                "DEMO-SFC-ISSUER-A",
                "HK",
                "SFC",
                "valid",
                ["manage_private_fund", "issue_fund_share_token", "invest_portfolio_equity"],
                "2027-12-31",
            ),
            (
                "custodian_A",
                "demo_trust_or_custody_operator",
                "DEMO-CUST-CUSTODIAN-A",
                "HK",
                "HKMA/SFC",
                "valid",
                ["custody_digital_asset", "operate_compute_revenue_oracle", "sign_settlement_transaction"],
                "2027-12-31",
            ),
            (
                "regulator",
                "demo_regulatory_observer",
                "DEMO-REGULATOR",
                "HK",
                "Regulator",
                "valid",
                ["read_audit_trail", "observe_chain_events"],
                None,
            ),
        ]
        kyc_aml_profiles = [
            ("alice", "user", "verified", "clear", "low", 1, "demo-kyc-provider", "hash-kyc-alice"),
            ("bob", "user", "verified", "clear", "low", 0, "demo-kyc-provider", "hash-kyc-bob"),
            ("issuer_A", "institution", "verified", "clear", "low", 0, "demo-institution-screening", "hash-aml-issuer-a"),
            ("custodian_A", "institution", "verified", "clear", "low", 0, "demo-institution-screening", "hash-aml-custodian-a"),
        ]
        legal_documents = [
            (
                "doc-hkpe-fund-ppm",
                "HK PE Fund I Private Placement Memorandum",
                "fund_offering_document",
                "hash-legal-hkpe-fund-ppm",
                "storage://legal/hk-pe-fund-i/ppm.pdf",
                "HK",
                "active",
            ),
            (
                "doc-aicomp-investment",
                "AI Compute Infrastructure Ltd Investment Agreement",
                "portfolio_investment_agreement",
                "hash-legal-aicomp-investment",
                "storage://legal/aicomp/investment-agreement.pdf",
                "HK",
                "active",
            ),
            (
                "doc-compute-revenue-attestation",
                "AI Compute Cluster A Revenue Attestation Pack",
                "revenue_attestation_pack",
                "hash-legal-compute-revenue-attestation",
                "storage://audit/aicomp/2026-q2-revenue-attestation.pdf",
                "HK",
                "active",
            ),
        ]
        rights_mappings = [
            (
                "rights-fund-share-hkpe-alice-001",
                "fund-share-hkpe-alice-001",
                "FundShareToken",
                "limited_partner_fund_interest",
                "doc-hkpe-fund-ppm",
                "Represents LP economic interest in HK PE Fund I for demo subscription units.",
                "Redeemable or transferable only under fund documents and manager approval.",
                {"requires_kyc": True, "professional_investor_only": True, "manager_approval_required": True},
            ),
            (
                "rights-portfolio-equity-aicomp-001",
                "portfolio-equity-aicomp-001",
                "PortfolioEquityRWA",
                "portfolio_company_equity_interest",
                "doc-aicomp-investment",
                "Represents the fund index record for equity exposure to AI Compute Infrastructure Ltd.",
                "Exit and proceeds follow the investment agreement and fund waterfall.",
                {"held_by_fund": True, "ic_approval_required": True, "secondary_transfer_restricted": True},
            ),
            (
                "rights-compute-token-aicomp-001",
                "compute-token-aicomp-001",
                "ComputePowerToken",
                "compute_revenue_benefit_record",
                "doc-compute-revenue-attestation",
                "Represents audited compute units and associated revenue evidence for AI Compute Cluster A.",
                "Revenue distribution requires oracle attestation and custodian confirmation.",
                {"oracle_attestation_required": True, "custodian_confirmation_required": True},
            ),
        ]
        custody_wallets = [
            ("wallet-issuer-a", "issuer_A", "institution", "0xissuerA_demo_wallet", "kms://demo/issuer-a", "demo-custody-provider", "active"),
            ("wallet-custodian-a", "custodian_A", "institution", "0xcustodianA_demo_wallet", "kms://demo/custodian-a", "demo-custody-provider", "active"),
            ("wallet-alice", "alice", "user", "0xalice_demo_wallet", "kms://demo/alice", "demo-custody-provider", "active"),
            ("wallet-bob", "bob", "user", "0xbob_demo_wallet", "kms://demo/bob", "demo-custody-provider", "active"),
        ]
        oracle_attestations = [
            (
                "oracle-compute-aicomp-2026q2",
                "demo_compute_metering_oracle",
                "AI Compute Cluster A",
                "compute-token-aicomp-001",
                "2026-Q2",
                "hash-compute-cluster-a",
                {"compute_units": 500, "revenue_amount_hkd": 25000, "meter_reading_hash": "hash-meter-aicomp-2026q2"},
                "verified",
            )
        ]
        for row in institutions:
            self.conn.execute(
                """
                INSERT INTO institutions (institution_id, name, did, status, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(institution_id) DO UPDATE SET
                  name = excluded.name,
                  did = excluded.did,
                  status = excluded.status,
                  role = excluded.role,
                  updated_at = excluded.updated_at
                """,
                (*row, now, now),
            )
        for row in users:
            self.conn.execute(
                """
                INSERT INTO users (user_id, institution_id, display_name, address, role, status, kyc_status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(address) DO UPDATE SET
                  display_name = excluded.display_name,
                  role = excluded.role,
                  status = excluded.status,
                  kyc_status = excluded.kyc_status,
                  updated_at = excluded.updated_at
                """,
                (*row, now, now),
            )
        for row in licensed_institutions:
            self.conn.execute(
                """
                INSERT INTO licensed_institutions (
                  institution_id, license_type, license_number, jurisdiction, regulator, status,
                  permitted_activities_json, valid_until, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(institution_id) DO UPDATE SET
                  license_type = excluded.license_type,
                  license_number = excluded.license_number,
                  jurisdiction = excluded.jurisdiction,
                  regulator = excluded.regulator,
                  status = excluded.status,
                  permitted_activities_json = excluded.permitted_activities_json,
                  valid_until = excluded.valid_until,
                  updated_at = excluded.updated_at
                """,
                (*row[:6], json.dumps(row[6], sort_keys=True), row[7], now, now),
            )
        for row in kyc_aml_profiles:
            self.conn.execute(
                """
                INSERT INTO kyc_aml_profiles (
                  subject, subject_type, kyc_status, aml_status, risk_rating,
                  professional_investor, sanctions_checked_at, source, evidence_hash, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(subject) DO UPDATE SET
                  subject_type = excluded.subject_type,
                  kyc_status = excluded.kyc_status,
                  aml_status = excluded.aml_status,
                  risk_rating = excluded.risk_rating,
                  professional_investor = excluded.professional_investor,
                  sanctions_checked_at = excluded.sanctions_checked_at,
                  source = excluded.source,
                  evidence_hash = excluded.evidence_hash,
                  updated_at = excluded.updated_at
                """,
                (*row[:6], now, row[6], row[7], now),
            )
        for row in legal_documents:
            self.conn.execute(
                """
                INSERT INTO legal_documents (
                  document_id, title, document_type, content_hash, storage_uri,
                  jurisdiction, status, effective_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(document_id) DO UPDATE SET
                  title = excluded.title,
                  document_type = excluded.document_type,
                  content_hash = excluded.content_hash,
                  storage_uri = excluded.storage_uri,
                  jurisdiction = excluded.jurisdiction,
                  status = excluded.status,
                  effective_at = excluded.effective_at
                """,
                (*row, now, now),
            )
        for row in rights_mappings:
            self.conn.execute(
                """
                INSERT INTO asset_rights_mappings (
                  rights_mapping_id, asset_id, asset_type, rights_type, document_id,
                  rights_summary, redemption_terms, transfer_restrictions_json,
                  status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                ON CONFLICT(rights_mapping_id) DO UPDATE SET
                  asset_id = excluded.asset_id,
                  asset_type = excluded.asset_type,
                  rights_type = excluded.rights_type,
                  document_id = excluded.document_id,
                  rights_summary = excluded.rights_summary,
                  redemption_terms = excluded.redemption_terms,
                  transfer_restrictions_json = excluded.transfer_restrictions_json,
                  status = excluded.status,
                  updated_at = excluded.updated_at
                """,
                (*row[:7], json.dumps(row[7], sort_keys=True), now, now),
            )
        for row in custody_wallets:
            self.conn.execute(
                """
                INSERT INTO custody_wallets (
                  wallet_id, owner, owner_type, wallet_address, kms_key_ref,
                  custody_provider, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(wallet_id) DO UPDATE SET
                  owner = excluded.owner,
                  owner_type = excluded.owner_type,
                  wallet_address = excluded.wallet_address,
                  kms_key_ref = excluded.kms_key_ref,
                  custody_provider = excluded.custody_provider,
                  status = excluded.status,
                  updated_at = excluded.updated_at
                """,
                (*row, now, now),
            )
        for row in oracle_attestations:
            self.conn.execute(
                """
                INSERT INTO oracle_attestations (
                  attestation_id, source, source_ref, subject_id, period,
                  content_hash, value_json, status, observed_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(attestation_id) DO UPDATE SET
                  source = excluded.source,
                  source_ref = excluded.source_ref,
                  subject_id = excluded.subject_id,
                  period = excluded.period,
                  content_hash = excluded.content_hash,
                  value_json = excluded.value_json,
                  status = excluded.status,
                  observed_at = excluded.observed_at
                """,
                (*row[:6], json.dumps(row[6], sort_keys=True), row[7], now, now),
            )
        self.conn.commit()

    def reset(self) -> None:
        self.conn.executescript(
            """
            DELETE FROM audit_logs;
            DELETE FROM chain_events;
            DELETE FROM transaction_records;
            DELETE FROM assets;
            DELETE FROM policy_evaluations;
            DELETE FROM tool_calls;
            DELETE FROM signature_requests;
            DELETE FROM task_queue;
            DELETE FROM agent_tasks;
            """
        )
        self.conn.commit()

    def list_institutions(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.conn.execute("SELECT * FROM institutions ORDER BY institution_id")
        ]

    def create_institution(self, body: dict[str, Any]) -> dict[str, Any]:
        institution_id = str(body.get("institution_id") or new_id("inst"))
        now = now_iso()
        self.conn.execute(
            """
            INSERT INTO institutions (institution_id, name, did, status, role, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                institution_id,
                str(body.get("name") or institution_id),
                body.get("did"),
                str(body.get("status") or "active"),
                str(body.get("role") or "issuer"),
                now,
                now,
            ),
        )
        self.conn.commit()
        return self.get_institution(institution_id) or {}

    def get_institution(self, institution_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM institutions WHERE institution_id = ? OR name = ?",
            (institution_id, institution_id),
        ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.conn.execute("SELECT * FROM users ORDER BY user_id")
        ]

    def create_user(self, body: dict[str, Any]) -> dict[str, Any]:
        user_id = str(body.get("user_id") or new_id("user"))
        address = str(body.get("address") or user_id)
        now = now_iso()
        self.conn.execute(
            """
            INSERT INTO users (
              user_id, institution_id, display_name, address, role,
              status, kyc_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                body.get("institution_id"),
                str(body.get("display_name") or address),
                address,
                str(body.get("role") or "trader"),
                str(body.get("status") or "active"),
                str(body.get("kyc_status") or "verified"),
                now,
                now,
            ),
        )
        self.conn.commit()
        return self.get_user(address) or {}

    def get_user(self, subject: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM users WHERE user_id = ? OR address = ? OR display_name = ?",
            (subject, subject, subject),
        ).fetchone()
        return dict(row) if row else None

    def list_licensed_institutions(self) -> list[dict[str, Any]]:
        return [
            self._licensed_institution_row(row)
            for row in self.conn.execute("SELECT * FROM licensed_institutions ORDER BY institution_id")
        ]

    def get_licensed_institution(self, institution_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM licensed_institutions WHERE institution_id = ?",
            (institution_id,),
        ).fetchone()
        return self._licensed_institution_row(row) if row else None

    def _licensed_institution_row(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["permitted_activities"] = json.loads(data.pop("permitted_activities_json"))
        return data

    def list_kyc_aml_profiles(self) -> list[dict[str, Any]]:
        return [
            self._kyc_aml_profile_row(row)
            for row in self.conn.execute("SELECT * FROM kyc_aml_profiles ORDER BY subject")
        ]

    def get_kyc_aml_profile(self, subject: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM kyc_aml_profiles WHERE subject = ?",
            (subject,),
        ).fetchone()
        return self._kyc_aml_profile_row(row) if row else None

    def _kyc_aml_profile_row(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["professional_investor"] = bool(data["professional_investor"])
        return data

    def list_legal_documents(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.conn.execute("SELECT * FROM legal_documents ORDER BY document_id")
        ]

    def get_legal_document(self, document_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM legal_documents WHERE document_id = ?",
            (document_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_legal_document_by_hash(self, content_hash: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM legal_documents WHERE content_hash = ?",
            (content_hash,),
        ).fetchone()
        return dict(row) if row else None

    def list_rights_mappings(self) -> list[dict[str, Any]]:
        return [
            self._rights_mapping_row(row)
            for row in self.conn.execute("SELECT * FROM asset_rights_mappings ORDER BY rights_mapping_id")
        ]

    def get_rights_mapping(self, asset_id: str | None = None, rights_mapping_id: str | None = None) -> dict[str, Any] | None:
        if rights_mapping_id:
            row = self.conn.execute(
                "SELECT * FROM asset_rights_mappings WHERE rights_mapping_id = ?",
                (rights_mapping_id,),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT * FROM asset_rights_mappings WHERE asset_id = ?",
                (asset_id,),
            ).fetchone()
        return self._rights_mapping_row(row) if row else None

    def _rights_mapping_row(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["transfer_restrictions"] = json.loads(data.pop("transfer_restrictions_json"))
        return data

    def list_custody_wallets(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.conn.execute("SELECT * FROM custody_wallets ORDER BY owner, wallet_id")
        ]

    def get_custody_wallet(self, owner: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM custody_wallets WHERE owner = ? AND status = 'active' ORDER BY wallet_id LIMIT 1",
            (owner,),
        ).fetchone()
        return dict(row) if row else None

    def insert_signature_request(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO signature_requests (
              signature_request_id, task_id, wallet_id, signer, payload_hash,
              signature_hash, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["signature_request_id"],
                record["task_id"],
                record["wallet_id"],
                record["signer"],
                record["payload_hash"],
                record["signature_hash"],
                record["status"],
                record["created_at"],
            ),
        )
        self.conn.commit()

    def list_signature_requests(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.conn.execute("SELECT * FROM signature_requests ORDER BY created_at, signature_request_id")
        ]

    def list_oracle_attestations(self) -> list[dict[str, Any]]:
        return [
            self._oracle_attestation_row(row)
            for row in self.conn.execute("SELECT * FROM oracle_attestations ORDER BY attestation_id")
        ]

    def get_oracle_attestation(
        self,
        attestation_id: str | None = None,
        source_ref: str | None = None,
        period: str | None = None,
        subject_id: str | None = None,
    ) -> dict[str, Any] | None:
        if attestation_id:
            row = self.conn.execute(
                "SELECT * FROM oracle_attestations WHERE attestation_id = ?",
                (attestation_id,),
            ).fetchone()
        else:
            row = self.conn.execute(
                """
                SELECT * FROM oracle_attestations
                WHERE source_ref = ? AND period = ? AND subject_id = ?
                ORDER BY observed_at DESC
                LIMIT 1
                """,
                (source_ref, period, subject_id),
            ).fetchone()
        return self._oracle_attestation_row(row) if row else None

    def _oracle_attestation_row(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["value"] = json.loads(data.pop("value_json"))
        return data

    def enqueue_task(self, task_id: str) -> None:
        now = now_iso()
        self.conn.execute(
            """
            INSERT INTO task_queue (queue_id, task_id, status, attempts, created_at, updated_at)
            VALUES (?, ?, 'queued', 0, ?, ?)
            """,
            (new_id("queue"), task_id, now, now),
        )
        self.conn.commit()

    def claim_next_task(self) -> dict[str, Any] | None:
        row = self.conn.execute(
            """
            SELECT * FROM task_queue
            WHERE status = 'queued'
            ORDER BY created_at
            LIMIT 1
            """
        ).fetchone()
        if not row:
            return None
        now = now_iso()
        self.conn.execute(
            """
            UPDATE task_queue
            SET status = 'processing', attempts = attempts + 1, locked_at = ?, updated_at = ?
            WHERE queue_id = ?
            """,
            (now, now, row["queue_id"]),
        )
        self.conn.commit()
        return dict(row)

    def mark_queue_done(self, task_id: str) -> None:
        now = now_iso()
        self.conn.execute(
            "UPDATE task_queue SET status = 'done', updated_at = ? WHERE task_id = ?",
            (now, task_id),
        )
        self.conn.commit()

    def mark_queue_failed(self, task_id: str, error: str) -> None:
        now = now_iso()
        self.conn.execute(
            "UPDATE task_queue SET status = 'failed', last_error = ?, updated_at = ? WHERE task_id = ?",
            (error, now, task_id),
        )
        self.conn.commit()

    def queue_stats(self) -> dict[str, Any]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS count FROM task_queue GROUP BY status ORDER BY status"
        ).fetchall()
        return {row["status"]: row["count"] for row in rows}

    def insert_task(self, task: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO agent_tasks (
              task_id, requester, requester_type, requester_signature, intent,
              intent_hash, constraints_json, authorization_scope_json,
              assigned_agent, plan_hash, policy_result, execution_status,
              related_tx_hashes_json, evidence_hash, idempotency_key,
              risk_preference, estimated_risk_level, error_code, error_message,
              created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task["task_id"],
                task["requester"],
                task["requester_type"],
                task.get("requester_signature"),
                task["intent"],
                task["intent_hash"],
                json.dumps(task.get("constraints", {}), sort_keys=True),
                json.dumps(task.get("authorization_scope", []), sort_keys=True),
                task["assigned_agent"],
                task.get("plan_hash"),
                task.get("policy_result"),
                task["execution_status"],
                json.dumps(task.get("related_tx_hashes", []), sort_keys=True),
                task.get("evidence_hash"),
                task["idempotency_key"],
                task.get("risk_preference"),
                task.get("estimated_risk_level"),
                task.get("error_code"),
                task.get("error_message"),
                task["created_at"],
                task["updated_at"],
            ),
        )
        self.conn.commit()

    def update_task(self, task_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = now_iso()
        assignments = []
        values: list[Any] = []
        for key, value in fields.items():
            if key == "constraints":
                key = "constraints_json"
                value = json.dumps(value, sort_keys=True)
            elif key == "authorization_scope":
                key = "authorization_scope_json"
                value = json.dumps(value, sort_keys=True)
            elif key == "related_tx_hashes":
                key = "related_tx_hashes_json"
                value = json.dumps(value, sort_keys=True)
            assignments.append(f"{key} = ?")
            values.append(value)
        values.append(task_id)
        self.conn.execute(f"UPDATE agent_tasks SET {', '.join(assignments)} WHERE task_id = ?", values)
        self.conn.commit()

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM agent_tasks WHERE task_id = ?", (task_id,)).fetchone()
        return self._task_row(row) if row else None

    def get_task_by_idempotency(self, requester: str, idempotency_key: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM agent_tasks WHERE requester = ? AND idempotency_key = ?",
            (requester, idempotency_key),
        ).fetchone()
        return self._task_row(row) if row else None

    def _task_row(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["constraints"] = json.loads(data.pop("constraints_json"))
        data["authorization_scope"] = json.loads(data.pop("authorization_scope_json"))
        data["related_tx_hashes"] = json.loads(data.pop("related_tx_hashes_json"))
        return data

    def insert_tool_call(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO tool_calls (
              tool_call_id, task_id, agent_id, tool_name, input_hash, output_hash,
              risk_level, policy_result, result, error_code, error_message,
              started_at, finished_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["tool_call_id"],
                record["task_id"],
                record["agent_id"],
                record["tool_name"],
                record["input_hash"],
                record.get("output_hash"),
                record["risk_level"],
                record.get("policy_result"),
                record.get("result"),
                record.get("error_code"),
                record.get("error_message"),
                record["started_at"],
                record.get("finished_at"),
            ),
        )
        self.conn.commit()

    def insert_policy_evaluation(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO policy_evaluations (
              policy_evaluation_id, task_id, agent_id, tool_name, policy_set_version,
              input_hash, result, reasons_json, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["policy_evaluation_id"],
                record["task_id"],
                record["agent_id"],
                record.get("tool_name"),
                record["policy_set_version"],
                record["input_hash"],
                record["result"],
                json.dumps(record.get("reasons", []), sort_keys=True),
                record["evaluated_at"],
            ),
        )
        self.conn.commit()

    def upsert_asset(self, asset: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO assets (
              asset_id, asset_type, issuer, owner, amount, metadata_hash, status,
              created_by_task_id, updated_by_task_id, chain_tx_hash, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_id) DO UPDATE SET
              owner = excluded.owner,
              amount = excluded.amount,
              status = excluded.status,
              updated_by_task_id = excluded.updated_by_task_id,
              chain_tx_hash = excluded.chain_tx_hash,
              updated_at = excluded.updated_at
            """,
            (
                asset["asset_id"],
                asset["asset_type"],
                asset["issuer"],
                asset["owner"],
                int(asset["amount"]),
                asset["metadata_hash"],
                asset["status"],
                asset["created_by_task_id"],
                asset["updated_by_task_id"],
                asset["chain_tx_hash"],
                asset["created_at"],
                asset["updated_at"],
            ),
        )
        self.conn.commit()

    def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        return dict(row) if row else None

    def insert_transaction(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO transaction_records (
              tx_hash, task_id, contract_name, method_name, caller, payload_hash,
              status, block_height, block_hash, submitted_at, confirmed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["tx_hash"],
                record["task_id"],
                record["contract_name"],
                record["method_name"],
                record["caller"],
                record["payload_hash"],
                record["status"],
                record["block_height"],
                record["block_hash"],
                record["submitted_at"],
                record["confirmed_at"],
            ),
        )
        self.conn.commit()

    def get_transaction(self, tx_hash: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM transaction_records WHERE tx_hash = ?", (tx_hash,)).fetchone()
        return dict(row) if row else None

    def next_block_height(self) -> int:
        row = self.conn.execute("SELECT COALESCE(MAX(block_height), 0) + 1 AS next_height FROM transaction_records").fetchone()
        return int(row["next_height"])

    def insert_chain_event(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO chain_events (
              event_id, tx_hash, block_height, block_hash, event_name,
              agent_task_id_hash, asset_id, event_payload_json, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["event_id"],
                record["tx_hash"],
                record["block_height"],
                record["block_hash"],
                record["event_name"],
                record["agent_task_id_hash"],
                record.get("asset_id"),
                json.dumps(record.get("event_payload", {}), sort_keys=True),
                record["observed_at"],
            ),
        )
        self.conn.commit()

    def insert_audit_log(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO audit_logs (
              log_id, operator, action, target_id, agent_task_id, agent_id,
              tx_hash, tool_call_hash, request_hash, result, evidence_hash,
              details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["log_id"],
                record["operator"],
                record["action"],
                record["target_id"],
                record["agent_task_id"],
                record["agent_id"],
                record.get("tx_hash"),
                record.get("tool_call_hash"),
                record["request_hash"],
                record["result"],
                record["evidence_hash"],
                json.dumps(record.get("details", {}), sort_keys=True),
                record["created_at"],
            ),
        )
        self.conn.commit()

    def audit_for_task(self, task_id: str) -> dict[str, Any]:
        logs = [self._audit_row(row) for row in self.conn.execute(
            "SELECT * FROM audit_logs WHERE agent_task_id = ? ORDER BY created_at, log_id",
            (task_id,),
        )]
        tool_calls = [dict(row) for row in self.conn.execute(
            "SELECT * FROM tool_calls WHERE task_id = ? ORDER BY started_at, tool_call_id",
            (task_id,),
        )]
        transactions = [dict(row) for row in self.conn.execute(
            "SELECT * FROM transaction_records WHERE task_id = ? ORDER BY block_height",
            (task_id,),
        )]
        events = [self._event_row(row) for row in self.conn.execute(
            """
            SELECT ce.* FROM chain_events ce
            JOIN transaction_records tr ON tr.tx_hash = ce.tx_hash
            WHERE tr.task_id = ?
            ORDER BY ce.block_height, ce.event_id
            """,
            (task_id,),
        )]
        return {
            "subject_id": task_id,
            "audit_logs": logs,
            "tool_calls": tool_calls,
            "transactions": transactions,
            "chain_events": events,
        }

    def audit_for_asset(self, asset_id: str) -> dict[str, Any]:
        logs = [self._audit_row(row) for row in self.conn.execute(
            "SELECT * FROM audit_logs WHERE target_id = ? ORDER BY created_at, log_id",
            (asset_id,),
        )]
        transactions = [dict(row) for row in self.conn.execute(
            """
            SELECT tr.* FROM transaction_records tr
            JOIN audit_logs al ON al.tx_hash = tr.tx_hash
            WHERE al.target_id = ?
            GROUP BY tr.tx_hash
            ORDER BY tr.block_height
            """,
            (asset_id,),
        )]
        task_ids = [row["agent_task_id"] for row in self.conn.execute(
            "SELECT DISTINCT agent_task_id FROM audit_logs WHERE target_id = ?",
            (asset_id,),
        )]
        tool_calls: list[dict[str, Any]] = []
        for task_id in task_ids:
            tool_calls.extend(
                dict(row)
                for row in self.conn.execute(
                    "SELECT * FROM tool_calls WHERE task_id = ? ORDER BY started_at, tool_call_id",
                    (task_id,),
                )
            )
        events = [self._event_row(row) for row in self.conn.execute(
            "SELECT * FROM chain_events WHERE asset_id = ? ORDER BY block_height, event_id",
            (asset_id,),
        )]
        return {
            "subject_id": asset_id,
            "audit_logs": logs,
            "tool_calls": tool_calls,
            "transactions": transactions,
            "chain_events": events,
        }

    def _audit_row(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["details"] = json.loads(data.pop("details_json"))
        return data

    def _event_row(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["event_payload"] = json.loads(data.pop("event_payload_json"))
        return data


@dataclass
class PolicyDecision:
    result: str
    reasons: list[str]
    risk_level: str


class PolicyEngine:
    version = "mock-policy-v1"

    def evaluate(self, task: dict[str, Any]) -> PolicyDecision:
        constraints = task["constraints"]
        intent = task["intent"]
        reasons: list[str] = []

        if not task.get("requester_signature"):
            reasons.append("missing_requester_signature")

        supported = {
            "issue_asset",
            "transfer_asset",
            "subscribe_fund_share",
            "invest_portfolio_equity",
            "record_compute_revenue",
        }
        if intent not in supported:
            reasons.append("unsupported_intent")

        amount = constraints.get("amount")
        if intent == "subscribe_fund_share":
            amount = constraints.get("share_units")
        elif intent == "invest_portfolio_equity":
            amount = constraints.get("equity_units")
        elif intent == "record_compute_revenue":
            amount = constraints.get("compute_units")
        if amount is None:
            reasons.append("missing_amount")
        else:
            try:
                if int(amount) <= 0:
                    reasons.append("amount_must_be_positive")
            except (TypeError, ValueError):
                reasons.append("amount_must_be_integer")

        if intent == "issue_asset":
            for field in ("asset_id", "asset_type", "owner"):
                if not constraints.get(field):
                    reasons.append(f"missing_{field}")
        elif intent == "transfer_asset":
            for field in ("asset_id", "from", "to"):
                if not constraints.get(field):
                    reasons.append(f"missing_{field}")
            if constraints.get("from") == constraints.get("to"):
                reasons.append("from_and_to_must_differ")
        elif intent == "subscribe_fund_share":
            for field in ("asset_id", "fund_id", "lp", "fund_manager", "share_units", "subscription_amount_hkd", "rights_mapping_id", "legal_document_hash"):
                if not constraints.get(field):
                    reasons.append(f"missing_{field}")
        elif intent == "invest_portfolio_equity":
            for field in ("asset_id", "fund_id", "portfolio_company", "fund_manager", "equity_units", "investment_amount_hkd", "rights_mapping_id", "legal_document_hash"):
                if not constraints.get(field):
                    reasons.append(f"missing_{field}")
        elif intent == "record_compute_revenue":
            for field in ("asset_id", "compute_project", "beneficiary", "compute_units", "revenue_amount_hkd", "rights_mapping_id", "legal_document_hash", "oracle_attestation_id"):
                if not constraints.get(field):
                    reasons.append(f"missing_{field}")

        risk_level = "medium" if intent in {"transfer_asset", "invest_portfolio_equity", "record_compute_revenue"} else "low"
        if amount is not None:
            try:
                if int(amount) >= 1_000_000:
                    risk_level = "high"
            except (TypeError, ValueError):
                pass

        return PolicyDecision(
            result="rejected" if reasons else "approved",
            reasons=reasons,
            risk_level=risk_level,
        )


class IdentityService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def verify(self, task: dict[str, Any]) -> dict[str, Any]:
        reasons: list[str] = []
        requester = task["requester"]
        requester_type = task["requester_type"]
        constraints = task["constraints"]

        if requester_type == "institution":
            institution = self.store.get_institution(requester)
            if not institution:
                reasons.append("requester_institution_not_found")
            elif institution["status"] != "active":
                reasons.append("requester_institution_inactive")
            profile = self.store.get_kyc_aml_profile(requester)
            if not profile:
                reasons.append("requester_institution_screening_missing")
            elif profile["aml_status"] != "clear":
                reasons.append("requester_institution_aml_not_clear")
            license_record = self.store.get_licensed_institution(requester)
            if not license_record:
                reasons.append("requester_license_missing")
            elif license_record["status"] != "valid":
                reasons.append("requester_license_invalid")
        elif requester_type == "user":
            user = self.store.get_user(requester)
            if not user:
                reasons.append("requester_user_not_found")
            elif user["status"] != "active":
                reasons.append("requester_user_inactive")
            elif user["kyc_status"] != "verified":
                reasons.append("requester_kyc_not_verified")
            profile = self.store.get_kyc_aml_profile(requester)
            if not profile:
                reasons.append("requester_kyc_aml_profile_missing")
            elif profile["kyc_status"] != "verified":
                reasons.append("requester_kyc_profile_not_verified")
            elif profile["aml_status"] != "clear":
                reasons.append("requester_aml_not_clear")
        else:
            reasons.append("unsupported_requester_type")

        if task["intent"] in {"issue_asset", "subscribe_fund_share"}:
            issuer = constraints.get("issuer") or requester
            owner = constraints.get("owner")
            if task["intent"] == "subscribe_fund_share":
                issuer = constraints.get("fund_manager")
                owner = constraints.get("lp")
            institution = self.store.get_institution(str(issuer))
            if not institution or institution["status"] != "active":
                reasons.append("issuer_institution_invalid")
            license_record = self.store.get_licensed_institution(str(issuer))
            if not license_record or license_record["status"] != "valid":
                reasons.append("issuer_license_invalid")
            # When a ZKP proof accompanies the task, the LP's KYC/AML is
            # delegated to the ZKP verifier step — skip plaintext checks here.
            lp_has_zkp = task["intent"] == "subscribe_fund_share" and bool(constraints.get("_zkp"))
            if not lp_has_zkp:
                user = self.store.get_user(str(owner)) if owner else None
                if not user or user["status"] != "active" or user["kyc_status"] != "verified":
                    reasons.append("owner_user_invalid")
                owner_profile = self.store.get_kyc_aml_profile(str(owner)) if owner else None
                if not owner_profile or owner_profile["aml_status"] != "clear":
                    reasons.append("owner_aml_profile_invalid")
                if task["intent"] == "subscribe_fund_share" and (not owner_profile or not owner_profile["professional_investor"]):
                    reasons.append("lp_professional_investor_required")
        elif task["intent"] == "transfer_asset":
            for field in ("from", "to"):
                user = self.store.get_user(str(constraints.get(field)))
                if not user or user["status"] != "active" or user["kyc_status"] != "verified":
                    reasons.append(f"{field}_user_invalid")
                profile = self.store.get_kyc_aml_profile(str(constraints.get(field)))
                if not profile or profile["aml_status"] != "clear":
                    reasons.append(f"{field}_aml_profile_invalid")
        elif task["intent"] == "invest_portfolio_equity":
            manager = self.store.get_institution(str(constraints.get("fund_manager")))
            if not manager or manager["status"] != "active":
                reasons.append("fund_manager_invalid")
            license_record = self.store.get_licensed_institution(str(constraints.get("fund_manager")))
            if not license_record or license_record["status"] != "valid":
                reasons.append("fund_manager_license_invalid")
        elif task["intent"] == "record_compute_revenue":
            operator = self.store.get_institution(str(constraints.get("operator") or requester))
            if not operator or operator["status"] != "active":
                reasons.append("operator_institution_invalid")
            license_record = self.store.get_licensed_institution(str(constraints.get("operator") or requester))
            if not license_record or license_record["status"] != "valid":
                reasons.append("operator_license_invalid")
            beneficiary = self.store.get_user(str(constraints.get("beneficiary")))
            if not beneficiary or beneficiary["status"] != "active" or beneficiary["kyc_status"] != "verified":
                reasons.append("beneficiary_user_invalid")
            profile = self.store.get_kyc_aml_profile(str(constraints.get("beneficiary")))
            if not profile or profile["aml_status"] != "clear":
                reasons.append("beneficiary_aml_profile_invalid")

        return {
            "verified": not reasons,
            "reasons": reasons,
            "requester": requester,
            "requester_type": requester_type,
        }


class ToolRecorder:
    def __init__(self, store: Store) -> None:
        self.store = store

    def call(
        self,
        task_id: str,
        agent_id: str,
        tool_name: str,
        payload: dict[str, Any],
        risk_level: str,
        fn,
        policy_result: str | None = None,
    ) -> Any:
        started_at = now_iso()
        tool_call_id = new_id("tool")
        input_hash = sha256_json(payload)
        try:
            output = fn()
            result = "success"
            error_code = None
            error_message = None
        except Exception as exc:
            output = {"error": str(exc)}
            result = "failed"
            error_code = exc.__class__.__name__
            error_message = str(exc)
        output_hash = sha256_json(output)
        self.store.insert_tool_call(
            {
                "tool_call_id": tool_call_id,
                "task_id": task_id,
                "agent_id": agent_id,
                "tool_name": tool_name,
                "input_hash": input_hash,
                "output_hash": output_hash,
                "risk_level": risk_level,
                "policy_result": policy_result,
                "result": result,
                "error_code": error_code,
                "error_message": error_message,
                "started_at": started_at,
                "finished_at": now_iso(),
            }
        )
        if result == "failed":
            raise RuntimeError(error_message)
        return output


class AuditService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def write(
        self,
        *,
        task_id: str,
        operator: str,
        action: str,
        target_id: str,
        agent_id: str,
        request_hash: str,
        result: str,
        details: dict[str, Any],
        tx_hash: str | None = None,
    ) -> str:
        evidence_hash = sha256_json(
            {
                "task_id": task_id,
                "operator": operator,
                "action": action,
                "target_id": target_id,
                "agent_id": agent_id,
                "request_hash": request_hash,
                "result": result,
                "details": details,
                "tx_hash": tx_hash,
            }
        )
        self.store.insert_audit_log(
            {
                "log_id": new_id("audit"),
                "operator": operator,
                "action": action,
                "target_id": target_id,
                "agent_task_id": task_id,
                "agent_id": agent_id,
                "tx_hash": tx_hash,
                "tool_call_hash": details.get("tool_call_hash"),
                "request_hash": request_hash,
                "result": result,
                "evidence_hash": evidence_hash,
                "details": details,
                "created_at": now_iso(),
            }
        )
        return evidence_hash


class ComplianceEvidenceService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def verify(self, task: dict[str, Any]) -> dict[str, Any]:
        subjects = self._subjects_for_task(task)
        profiles: dict[str, Any] = {}
        licenses: dict[str, Any] = {}
        reasons: list[str] = []

        zkp_proven = task["constraints"].get("_zkp_proven", False)
        lp_subject = str(task["constraints"].get("lp", "")) if task["intent"] == "subscribe_fund_share" else ""

        for subject, subject_type in subjects.items():
            # ZKP-proven LP: skip plaintext KYC lookup, treat as verified
            if zkp_proven and subject == lp_subject and subject_type == "user":
                profiles[subject] = {"zkp_proven": True, "subject": subject}
                continue
            profile = self.store.get_kyc_aml_profile(subject)
            if not profile:
                reasons.append(f"{subject}_kyc_aml_missing")
            elif profile["kyc_status"] != "verified" or profile["aml_status"] != "clear":
                reasons.append(f"{subject}_kyc_aml_not_clear")
            else:
                profiles[subject] = profile

            if subject_type == "institution":
                license_record = self.store.get_licensed_institution(subject)
                if not license_record:
                    reasons.append(f"{subject}_license_missing")
                elif license_record["status"] != "valid":
                    reasons.append(f"{subject}_license_invalid")
                else:
                    licenses[subject] = license_record

        if task["intent"] == "subscribe_fund_share":
            lp = str(task["constraints"].get("lp"))
            if not (zkp_proven and lp == lp_subject):
                profile = profiles.get(lp) or self.store.get_kyc_aml_profile(lp)
                if not profile or not profile.get("professional_investor"):
                    reasons.append("lp_professional_investor_required")

        if reasons:
            raise ValueError(",".join(reasons))
        return {
            "verified": True,
            "subjects": subjects,
            "profiles": profiles,
            "licenses": licenses,
        }

    def _subjects_for_task(self, task: dict[str, Any]) -> dict[str, str]:
        c = task["constraints"]
        subjects = {task["requester"]: task["requester_type"]}
        if task["intent"] == "subscribe_fund_share":
            subjects[str(c.get("lp"))] = "user"
            subjects[str(c.get("fund_manager"))] = "institution"
        elif task["intent"] == "invest_portfolio_equity":
            subjects[str(c.get("fund_manager"))] = "institution"
        elif task["intent"] == "record_compute_revenue":
            subjects[str(c.get("operator", task["requester"]))] = "institution"
            subjects[str(c.get("beneficiary"))] = "user"
        elif task["intent"] == "issue_asset":
            subjects[str(c.get("issuer", task["requester"]))] = "institution"
            subjects[str(c.get("owner"))] = "user"
        elif task["intent"] == "transfer_asset":
            subjects[str(c.get("from"))] = "user"
            subjects[str(c.get("to"))] = "user"
        return {key: value for key, value in subjects.items() if key and key != "None"}


class LegalEvidenceService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def verify(self, task: dict[str, Any]) -> dict[str, Any]:
        c = task["constraints"]
        mapping = self.store.get_rights_mapping(
            asset_id=c.get("asset_id"),
            rights_mapping_id=c.get("rights_mapping_id"),
        )
        if not mapping:
            raise ValueError("rights_mapping_not_found")
        if mapping["asset_id"] != c.get("asset_id"):
            raise ValueError("rights_mapping_asset_mismatch")
        if mapping["asset_type"] != c.get("asset_type"):
            raise ValueError("rights_mapping_asset_type_mismatch")
        if mapping["status"] != "active":
            raise ValueError("rights_mapping_inactive")

        document = self.store.get_legal_document(mapping["document_id"])
        if not document:
            raise ValueError("legal_document_not_found")
        if document["status"] != "active":
            raise ValueError("legal_document_inactive")
        if c.get("legal_document_hash") and c["legal_document_hash"] != document["content_hash"]:
            raise ValueError("legal_document_hash_mismatch")

        return {
            "verified": True,
            "rights_mapping": mapping,
            "legal_document": document,
        }


class CustodySigningService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def sign(self, task: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        signer = self._signer_for_task(task)
        wallet = self.store.get_custody_wallet(signer)
        if not wallet:
            raise ValueError(f"active_wallet_not_found:{signer}")
        payload_hash = sha256_json(
            {
                "task_id": task["task_id"],
                "intent_hash": task["intent_hash"],
                "payload": payload,
            }
        )
        signature_hash = "sig_" + sha256_json(
            {
                "payload_hash": payload_hash,
                "wallet_id": wallet["wallet_id"],
                "kms_key_ref": wallet["kms_key_ref"],
            }
        )[:48]
        record = {
            "signature_request_id": new_id("sigreq"),
            "task_id": task["task_id"],
            "wallet_id": wallet["wallet_id"],
            "signer": signer,
            "payload_hash": payload_hash,
            "signature_hash": signature_hash,
            "status": "signed",
            "created_at": now_iso(),
        }
        self.store.insert_signature_request(record)
        return {
            **record,
            "wallet_address": wallet["wallet_address"],
            "kms_key_ref": wallet["kms_key_ref"],
            "custody_provider": wallet["custody_provider"],
            "signing_mode": "mock_kms_hsm",
        }

    def _signer_for_task(self, task: dict[str, Any]) -> str:
        c = task["constraints"]
        if task["intent"] in {"subscribe_fund_share", "invest_portfolio_equity"}:
            return str(c.get("fund_manager"))
        if task["intent"] == "record_compute_revenue":
            return str(c.get("operator", task["requester"]))
        if task["intent"] == "issue_asset":
            return str(c.get("issuer", task["requester"]))
        if task["intent"] == "transfer_asset":
            return str(c.get("from", task["requester"]))
        return str(task["requester"])


class OracleAttestationService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def verify(self, task: dict[str, Any]) -> dict[str, Any]:
        c = task["constraints"]
        attestation = self.store.get_oracle_attestation(
            attestation_id=c.get("oracle_attestation_id"),
            source_ref=c.get("compute_project"),
            period=c.get("revenue_period", "current"),
            subject_id=c.get("asset_id"),
        )
        if not attestation:
            raise ValueError("oracle_attestation_not_found")
        if attestation["status"] != "verified":
            raise ValueError("oracle_attestation_not_verified")
        if c.get("attestation_hash") and c["attestation_hash"] != attestation["content_hash"]:
            raise ValueError("oracle_attestation_hash_mismatch")

        value = attestation["value"]
        if int(value.get("compute_units", 0)) != int(c.get("compute_units", 0)):
            raise ValueError("oracle_compute_units_mismatch")
        if int(value.get("revenue_amount_hkd", 0)) != int(c.get("revenue_amount_hkd", 0)):
            raise ValueError("oracle_revenue_amount_mismatch")

        return {
            "verified": True,
            "attestation": attestation,
        }


class ChainAdapter:
    adapter_name = "base"

    def submit(self, *, task: dict[str, Any], method_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class MockChainAdapter(ChainAdapter):
    adapter_name = "mock"

    def __init__(self, store: Store) -> None:
        self.store = store

    def submit(self, *, task: dict[str, Any], method_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        block_height = self.store.next_block_height()
        tx_payload = {
            "task_id": task["task_id"],
            "method_name": method_name,
            "payload": payload,
            "block_height": block_height,
            "submitted_at_ms": now_ms(),
        }
        tx_hash = "0x" + sha256_json(tx_payload)[:48]
        block_hash = "0x" + sha256_json({"block_height": block_height, "tx_hash": tx_hash})[:48]
        record = {
            "tx_hash": tx_hash,
            "task_id": task["task_id"],
            "contract_name": "AssetTokenization",
            "method_name": method_name,
            "caller": task["assigned_agent"],
            "payload_hash": sha256_json(payload),
            "status": "confirmed",
            "block_height": block_height,
            "block_hash": block_hash,
            "submitted_at": now_iso(),
            "confirmed_at": now_iso(),
        }
        self.store.insert_transaction(record)
        self.store.insert_chain_event(
            {
                "event_id": new_id("evt"),
                "tx_hash": tx_hash,
                "block_height": block_height,
                "block_hash": block_hash,
                "event_name": payload["event_name"],
                "agent_task_id_hash": task["intent_hash"],
                "asset_id": payload.get("asset_id"),
                "event_payload": payload,
                "observed_at": now_iso(),
            }
        )
        return record


class HttpChainAdapter(ChainAdapter):
    adapter_name = "http"

    def __init__(self, endpoint: str, store: Store) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.store = store

    def submit(self, *, task: dict[str, Any], method_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(
            {
                "task_id": task["task_id"],
                "agent_task_hash": task["intent_hash"],
                "contract_name": "AssetTokenization",
                "method_name": method_name,
                "caller": task["assigned_agent"],
                "payload": payload,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.endpoint}/transactions",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"chain adapter request failed: {exc}") from exc

        tx_hash = data.get("tx_hash")
        if not tx_hash:
            raise RuntimeError("chain adapter response missing tx_hash")
        block_height = int(data.get("block_height") or self.store.next_block_height())
        block_hash = data.get("block_hash") or "0x" + sha256_json({"block_height": block_height, "tx_hash": tx_hash})[:48]
        record = {
            "tx_hash": tx_hash,
            "task_id": task["task_id"],
            "contract_name": data.get("contract_name", "AssetTokenization"),
            "method_name": data.get("method_name", method_name),
            "caller": data.get("caller", task["assigned_agent"]),
            "payload_hash": data.get("payload_hash", sha256_json(payload)),
            "status": data.get("status", "confirmed"),
            "block_height": block_height,
            "block_hash": block_hash,
            "submitted_at": data.get("submitted_at", now_iso()),
            "confirmed_at": data.get("confirmed_at", now_iso()),
        }
        self.store.insert_transaction(record)
        self.store.insert_chain_event(
            {
                "event_id": new_id("evt"),
                "tx_hash": tx_hash,
                "block_height": block_height,
                "block_hash": block_hash,
                "event_name": payload.get("event_name", method_name),
                "agent_task_id_hash": task["intent_hash"],
                "asset_id": payload.get("asset_id"),
                "event_payload": data.get("event_payload", payload),
                "observed_at": now_iso(),
            }
        )
        return record


def build_chain_adapter(store: Store) -> ChainAdapter:
    adapter = os.environ.get("CHAIN_ADAPTER", "mock").lower()
    if adapter == "http":
        endpoint = os.environ.get("CHAIN_RPC_URL")
        if not endpoint:
            raise RuntimeError("CHAIN_RPC_URL is required when CHAIN_ADAPTER=http")
        return HttpChainAdapter(endpoint, store)
    return MockChainAdapter(store)


class AssetService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def issue(self, task: dict[str, Any], tx_hash: str) -> dict[str, Any]:
        c = task["constraints"]
        existing = self.store.get_asset(c["asset_id"])
        if existing and existing["status"] not in {"burned", "redeemed"}:
            raise ValueError(f"asset already exists: {c['asset_id']}")
        asset = {
            "asset_id": c["asset_id"],
            "asset_type": c["asset_type"],
            "issuer": c.get("issuer", task["requester"]),
            "owner": c["owner"],
            "amount": int(c["amount"]),
            "metadata_hash": c.get("metadata_hash", sha256_json(c)),
            "status": "issued",
            "created_by_task_id": task["task_id"],
            "updated_by_task_id": task["task_id"],
            "chain_tx_hash": tx_hash,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        self.store.upsert_asset(asset)
        return asset

    def transfer(self, task: dict[str, Any], tx_hash: str) -> dict[str, Any]:
        c = task["constraints"]
        asset = self.store.get_asset(c["asset_id"])
        if not asset:
            raise ValueError(f"asset not found: {c['asset_id']}")
        if asset["status"] not in {"issued", "transferred"}:
            raise ValueError(f"asset not transferable in status {asset['status']}")
        if asset["owner"] != c["from"]:
            raise ValueError(f"owner mismatch: expected {asset['owner']}, got {c['from']}")
        if int(asset["amount"]) != int(c["amount"]):
            raise ValueError("MVP supports full-balance transfer only")
        updated = dict(asset)
        updated["owner"] = c["to"]
        updated["status"] = "transferred"
        updated["updated_by_task_id"] = task["task_id"]
        updated["chain_tx_hash"] = tx_hash
        updated["updated_at"] = now_iso()
        self.store.upsert_asset(updated)
        return updated

    def record_compute_revenue(self, task: dict[str, Any], tx_hash: str) -> dict[str, Any]:
        c = task["constraints"]
        existing = self.store.get_asset(c["asset_id"])
        now = now_iso()
        asset = existing or {
            "asset_id": c["asset_id"],
            "asset_type": "ComputePowerToken",
            "issuer": c.get("operator", task["requester"]),
            "owner": c["beneficiary"],
            "amount": int(c["compute_units"]),
            "metadata_hash": c.get("metadata_hash", sha256_json(c)),
            "status": "issued",
            "created_by_task_id": task["task_id"],
            "created_at": now,
        }
        asset.update(
            {
                "owner": c["beneficiary"],
                "amount": int(c["compute_units"]),
                "status": "issued",
                "updated_by_task_id": task["task_id"],
                "chain_tx_hash": tx_hash,
                "updated_at": now,
            }
        )
        self.store.upsert_asset(asset)
        return asset


class Orchestrator:
    def __init__(self, store: Store, chain: ChainAdapter) -> None:
        self.store = store
        self.identity = IdentityService(store)
        self.policy = PolicyEngine()
        self.tools = ToolRecorder(store)
        self.audit = AuditService(store)
        self.compliance = ComplianceEvidenceService(store)
        self.legal = LegalEvidenceService(store)
        self.custody = CustodySigningService(store)
        self.oracle = OracleAttestationService(store)
        self.chain = chain
        self.assets = AssetService(store)
        _zkp_dir = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "zkp")
        )
        self.zkp: Any = build_zkp_verifier(os.path.join(_zkp_dir, "build"))
        if self.zkp is not None:
            _registry_path = os.path.join(_zkp_dir, "registry.json")
            if os.path.exists(_registry_path):
                with open(_registry_path) as _fh:
                    _reg = json.load(_fh)
                self.zkp.add_root(_reg.get("merkleRoot", ""))

    def create_task(self, body: dict[str, Any], idempotency_key: str | None = None) -> dict[str, Any]:
        requester = str(body.get("requester") or "anonymous")
        effective_idempotency_key = str(body.get("idempotency_key") or idempotency_key or new_id("idem"))
        existing = self.store.get_task_by_idempotency(requester, effective_idempotency_key)
        if existing:
            return existing

        intent = self._normalize_intent(body)
        constraints = self._normalize_constraints(body, intent)
        task = {
            "task_id": new_id("task"),
            "requester": requester,
            "requester_type": body.get("requester_type", "institution"),
            "requester_signature": body.get("requester_signature"),
            "intent": intent,
            "intent_hash": sha256_json({"intent": intent, "constraints": constraints, "requester": requester}),
            "constraints": constraints,
            "authorization_scope": body.get("authorization_scope", [intent]),
            "assigned_agent": "orchestrator-agent",
            "plan_hash": None,
            "policy_result": None,
            "execution_status": "created",
            "related_tx_hashes": [],
            "evidence_hash": None,
            "idempotency_key": effective_idempotency_key,
            "risk_preference": body.get("risk_preference", "medium"),
            "estimated_risk_level": "medium",
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        self.store.insert_task(task)
        self.store.enqueue_task(task["task_id"])
        return self.store.get_task(task["task_id"]) or task

    def execute(self, task_id: str) -> None:
        task = self.store.get_task(task_id)
        if not task:
            raise ValueError(f"task not found: {task_id}")

        try:
            self.store.update_task(task_id, execution_status="planning")
            plan = self._plan(task)
            plan_hash = sha256_json(plan)
            self.store.update_task(task_id, plan_hash=plan_hash, assigned_agent="orchestrator-agent")

            task = self.store.get_task(task_id) or task
            self.store.update_task(task_id, execution_status="policy_checking")
            identity_result = self.tools.call(
                task_id,
                "identity-agent",
                "tool.identity.verifySubject",
                {"task": task},
                "medium",
                lambda: self.identity.verify(task),
            )
            if not identity_result["verified"]:
                self.store.update_task(
                    task_id,
                    policy_result="rejected",
                    execution_status="policy_rejected",
                    error_code="IdentityRejected",
                    error_message=",".join(identity_result["reasons"]),
                )
                self.audit.write(
                    task_id=task_id,
                    operator=task["requester"],
                    action="identity_rejected",
                    target_id=task["constraints"].get("asset_id", task_id),
                    agent_id="audit-agent",
                    request_hash=task["intent_hash"],
                    result="failed",
                    details=identity_result,
                )
                return

            decision = self.tools.call(
                task_id,
                "compliance-agent",
                "tool.policy.evaluate",
                {"task": task},
                "medium",
                lambda: self._evaluate_policy(task),
            )
            policy_result = decision["result"]
            self.store.update_task(
                task_id,
                policy_result=policy_result,
                estimated_risk_level=decision["risk_level"],
            )
            if policy_result != "approved":
                self.store.update_task(task_id, execution_status="policy_rejected")
                self.audit.write(
                    task_id=task_id,
                    operator=task["requester"],
                    action="policy_rejected",
                    target_id=task["constraints"].get("asset_id", task_id),
                    agent_id="audit-agent",
                    request_hash=task["intent_hash"],
                    result="failed",
                    details=decision,
                )
                return

            task = self.store.get_task(task_id) or task
            _zkp_payload = task["constraints"].get("_zkp")
            if _zkp_payload and self.zkp is not None:
                def _run_zkp(t=task, p=_zkp_payload):
                    # taskHashCommitment is LP-chosen (publicSignals[1]); nullifier
                    # consumption provides replay protection across tasks.
                    result = self.zkp.verify(
                        p["proof"],
                        p["publicSignals"],
                        p["publicSignals"][1],
                    )
                    updated = dict(t["constraints"])
                    updated["_zkp_proven"] = True
                    updated["_zkp_nullifier"] = result["nullifier_hash"]
                    self.store.update_task(t["task_id"], constraints=updated)
                    return result

                self.tools.call(
                    task_id,
                    "privacy-agent",
                    "tool.privacy.verifyZkpProof",
                    {"task": task},
                    "high",
                    _run_zkp,
                    policy_result="approved",
                )
                task = self.store.get_task(task_id) or task

            self.tools.call(
                task_id,
                "compliance-agent",
                "tool.compliance.verifyKycAml",
                {"task": task},
                "medium",
                lambda: self.compliance.verify(task),
                policy_result="approved",
            )
            if task["intent"] in {"subscribe_fund_share", "invest_portfolio_equity", "record_compute_revenue"}:
                self.tools.call(
                    task_id,
                    "legal-agent",
                    "tool.legal.verifyRightsMapping",
                    {"task": task},
                    "high",
                    lambda: self.legal.verify(task),
                    policy_result="approved",
                )
            if task["intent"] == "record_compute_revenue":
                self.tools.call(
                    task_id,
                    "oracle-agent",
                    "tool.oracle.verifyAttestation",
                    {"task": task},
                    "high",
                    lambda: self.oracle.verify(task),
                    policy_result="approved",
                )

            self.store.update_task(task_id, execution_status="tool_executing")
            if task["intent"] == "issue_asset":
                tx_record = self._issue(task)
            elif task["intent"] == "transfer_asset":
                tx_record = self._transfer(task)
            elif task["intent"] == "subscribe_fund_share":
                tx_record = self._subscribe_fund_share(task)
            elif task["intent"] == "invest_portfolio_equity":
                tx_record = self._invest_portfolio_equity(task)
            elif task["intent"] == "record_compute_revenue":
                tx_record = self._record_compute_revenue(task)
            else:
                raise ValueError(f"unsupported intent: {task['intent']}")

            task = self.store.get_task(task_id) or task
            self.store.update_task(task_id, execution_status="auditing")
            evidence_hash = self.audit.write(
                task_id=task_id,
                operator=task["requester"],
                action=f"{task['intent']}_completed",
                target_id=task["constraints"]["asset_id"],
                agent_id="audit-agent",
                tx_hash=tx_record["tx_hash"],
                request_hash=task["intent_hash"],
                result="success",
                details={
                    "plan_hash": task.get("plan_hash"),
                    "policy_result": task.get("policy_result"),
                    "tx_hash": tx_record["tx_hash"],
                    "block_height": tx_record["block_height"],
                },
            )
            related = task.get("related_tx_hashes", [])
            if tx_record["tx_hash"] not in related:
                related.append(tx_record["tx_hash"])
            self.store.update_task(
                task_id,
                execution_status="succeeded",
                related_tx_hashes=related,
                evidence_hash=evidence_hash,
            )
        except Exception as exc:
            self.store.update_task(
                task_id,
                execution_status="failed",
                error_code=exc.__class__.__name__,
                error_message=str(exc),
            )
            task = self.store.get_task(task_id) or {"requester": "unknown", "intent_hash": task_id, "constraints": {}}
            self.audit.write(
                task_id=task_id,
                operator=task["requester"],
                action=f"{task.get('intent', 'task')}_failed",
                target_id=task.get("constraints", {}).get("asset_id", task_id),
                agent_id="audit-agent",
                request_hash=task.get("intent_hash", task_id),
                result="failed",
                details={"error_code": exc.__class__.__name__, "error_message": str(exc)},
            )

    def _plan(self, task: dict[str, Any]) -> dict[str, Any]:
        tools = ["tool.identity.verifySubject", "tool.policy.evaluate"]
        if task["intent"] in {"issue_asset", "subscribe_fund_share", "invest_portfolio_equity", "record_compute_revenue"}:
            if task["constraints"].get("_zkp") and self.zkp is not None:
                tools.append("tool.privacy.verifyZkpProof")
            tools.append("tool.compliance.verifyKycAml")
            if task["intent"] in {"subscribe_fund_share", "invest_portfolio_equity", "record_compute_revenue"}:
                tools.append("tool.legal.verifyRightsMapping")
            if task["intent"] == "record_compute_revenue":
                tools.append("tool.oracle.verifyAttestation")
            tools.extend(["tool.asset.issue", "tool.custody.signTransaction", "tool.transaction.submit", "tool.audit.writeEvidence"])
        elif task["intent"] == "transfer_asset":
            tools.extend(["tool.compliance.verifyKycAml", "tool.asset.query", "tool.asset.transfer", "tool.custody.signTransaction", "tool.transaction.submit", "tool.audit.writeEvidence"])
        return {
            "task_id": task["task_id"],
            "planner": "orchestrator-agent",
            "intent": task["intent"],
            "steps": tools,
            "created_at": now_iso(),
        }

    def _evaluate_policy(self, task: dict[str, Any]) -> dict[str, Any]:
        decision = self.policy.evaluate(task)
        self.store.insert_policy_evaluation(
            {
                "policy_evaluation_id": new_id("policy"),
                "task_id": task["task_id"],
                "agent_id": "compliance-agent",
                "tool_name": "tool.policy.evaluate",
                "policy_set_version": self.policy.version,
                "input_hash": sha256_json(task),
                "result": decision.result,
                "reasons": decision.reasons,
                "evaluated_at": now_iso(),
            }
        )
        return {
            "result": decision.result,
            "reasons": decision.reasons,
            "risk_level": decision.risk_level,
            "policy_set_version": self.policy.version,
        }

    def _sign_payload(self, task: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        signature = self.tools.call(
            task["task_id"],
            "custody-agent",
            "tool.custody.signTransaction",
            {"payload": payload},
            "high",
            lambda: self.custody.sign(task, payload),
            policy_result="approved",
        )
        return {
            **payload,
            "signature_request_id": signature["signature_request_id"],
            "signer_wallet": signature["wallet_address"],
            "signature_hash": signature["signature_hash"],
            "custody_provider": signature["custody_provider"],
        }

    def _issue(self, task: dict[str, Any]) -> dict[str, Any]:
        c = task["constraints"]
        payload = {
            "event_name": "AssetIssued",
            "asset_id": c["asset_id"],
            "asset_type": c["asset_type"],
            "owner": c["owner"],
            "amount": int(c["amount"]),
            "metadata_hash": c.get("metadata_hash", sha256_json(c)),
        }
        signed_payload = self._sign_payload(task, payload)
        tx_record = self.tools.call(
            task["task_id"],
            "transaction-agent",
            "tool.transaction.submit",
            signed_payload,
            "medium",
            lambda: self.chain.submit(task=task, method_name="issueAsset", payload=signed_payload),
            policy_result="approved",
        )
        self.tools.call(
            task["task_id"],
            "asset-agent",
            "tool.asset.issue",
            payload,
            "medium",
            lambda: self.assets.issue(task, tx_record["tx_hash"]),
            policy_result="approved",
        )
        return tx_record

    def _transfer(self, task: dict[str, Any]) -> dict[str, Any]:
        c = task["constraints"]
        payload = {
            "event_name": "AssetTransferred",
            "asset_id": c["asset_id"],
            "from": c["from"],
            "to": c["to"],
            "amount": int(c["amount"]),
        }
        self.tools.call(
            task["task_id"],
            "asset-agent",
            "tool.asset.query",
            {"asset_id": c["asset_id"]},
            "low",
            lambda: self.store.get_asset(c["asset_id"]) or (_ for _ in ()).throw(ValueError("asset not found")),
            policy_result="approved",
        )
        signed_payload = self._sign_payload(task, payload)
        tx_record = self.tools.call(
            task["task_id"],
            "transaction-agent",
            "tool.transaction.submit",
            signed_payload,
            "medium",
            lambda: self.chain.submit(task=task, method_name="transferAsset", payload=signed_payload),
            policy_result="approved",
        )
        self.tools.call(
            task["task_id"],
            "asset-agent",
            "tool.asset.transfer",
            payload,
            "medium",
            lambda: self.assets.transfer(task, tx_record["tx_hash"]),
            policy_result="approved",
        )
        return tx_record

    def _subscribe_fund_share(self, task: dict[str, Any]) -> dict[str, Any]:
        c = task["constraints"]
        payload = {
            "event_name": "FundShareTokenIssued",
            "asset_id": c["asset_id"],
            "asset_type": "FundShareToken",
            "fund_id": c["fund_id"],
            "lp": c["lp"],
            "owner": c["lp"],
            "fund_manager": c["fund_manager"],
            "amount": int(c["share_units"]),
            "subscription_amount_hkd": int(c["subscription_amount_hkd"]),
            "metadata_hash": c.get("metadata_hash", sha256_json(c)),
            "rights_mapping_id": c.get("rights_mapping_id"),
            "legal_document_hash": c.get("legal_document_hash"),
        }
        signed_payload = self._sign_payload(task, payload)
        tx_record = self.tools.call(
            task["task_id"],
            "transaction-agent",
            "tool.transaction.submit",
            signed_payload,
            "medium",
            lambda: self.chain.submit(task=task, method_name="issueFundShareToken", payload=signed_payload),
            policy_result="approved",
        )
        self.tools.call(
            task["task_id"],
            "asset-agent",
            "tool.asset.issue",
            payload,
            "medium",
            lambda: self.assets.issue(task, tx_record["tx_hash"]),
            policy_result="approved",
        )
        return tx_record

    def _invest_portfolio_equity(self, task: dict[str, Any]) -> dict[str, Any]:
        c = task["constraints"]
        payload = {
            "event_name": "PortfolioEquityRWAIssued",
            "asset_id": c["asset_id"],
            "asset_type": "PortfolioEquityRWA",
            "fund_id": c["fund_id"],
            "portfolio_company": c["portfolio_company"],
            "owner": c.get("owner", c["fund_id"]),
            "fund_manager": c["fund_manager"],
            "amount": int(c["equity_units"]),
            "investment_amount_hkd": int(c["investment_amount_hkd"]),
            "metadata_hash": c.get("metadata_hash", sha256_json(c)),
            "rights_mapping_id": c.get("rights_mapping_id"),
            "legal_document_hash": c.get("legal_document_hash"),
        }
        signed_payload = self._sign_payload(task, payload)
        tx_record = self.tools.call(
            task["task_id"],
            "transaction-agent",
            "tool.transaction.submit",
            signed_payload,
            "medium",
            lambda: self.chain.submit(task=task, method_name="issuePortfolioEquityRWA", payload=signed_payload),
            policy_result="approved",
        )
        self.tools.call(
            task["task_id"],
            "asset-agent",
            "tool.asset.issue",
            payload,
            "medium",
            lambda: self.assets.issue(task, tx_record["tx_hash"]),
            policy_result="approved",
        )
        return tx_record

    def _record_compute_revenue(self, task: dict[str, Any]) -> dict[str, Any]:
        c = task["constraints"]
        payload = {
            "event_name": "ComputeRevenueRecorded",
            "asset_id": c["asset_id"],
            "asset_type": "ComputePowerToken",
            "compute_project": c["compute_project"],
            "operator": c.get("operator", task["requester"]),
            "owner": c["beneficiary"],
            "beneficiary": c["beneficiary"],
            "amount": int(c["compute_units"]),
            "compute_units": int(c["compute_units"]),
            "revenue_amount_hkd": int(c["revenue_amount_hkd"]),
            "revenue_period": c.get("revenue_period", "current"),
            "metadata_hash": c.get("metadata_hash", sha256_json(c)),
            "rights_mapping_id": c.get("rights_mapping_id"),
            "legal_document_hash": c.get("legal_document_hash"),
            "oracle_attestation_id": c.get("oracle_attestation_id"),
        }
        signed_payload = self._sign_payload(task, payload)
        tx_record = self.tools.call(
            task["task_id"],
            "transaction-agent",
            "tool.transaction.submit",
            signed_payload,
            "medium",
            lambda: self.chain.submit(task=task, method_name="recordComputeRevenue", payload=signed_payload),
            policy_result="approved",
        )
        self.tools.call(
            task["task_id"],
            "asset-agent",
            "tool.asset.recordComputeRevenue",
            payload,
            "medium",
            lambda: self.assets.record_compute_revenue(task, tx_record["tx_hash"]),
            policy_result="approved",
        )
        return tx_record

    def _normalize_intent(self, body: dict[str, Any]) -> str:
        intent = str(body.get("intent", "")).strip()
        if intent in {"issue_asset", "transfer_asset", "subscribe_fund_share", "invest_portfolio_equity", "record_compute_revenue"}:
            return intent

        lowered = intent.lower()
        if "subscribe" in lowered or "认购" in lowered or "fund share" in lowered:
            return "subscribe_fund_share"
        if "portfolio" in lowered or "投资项目" in lowered or "股权" in lowered:
            return "invest_portfolio_equity"
        if "compute" in lowered or "算力" in lowered or "收益" in lowered:
            return "record_compute_revenue"
        if "issue" in lowered or "发行" in lowered:
            return "issue_asset"
        if "transfer" in lowered or "转让" in lowered:
            return "transfer_asset"
        raise ValueError("intent must be issue_asset, transfer_asset, subscribe_fund_share, invest_portfolio_equity, or record_compute_revenue")

    def _normalize_constraints(self, body: dict[str, Any], intent: str) -> dict[str, Any]:
        constraints = dict(body.get("constraints") or {})
        for key in (
            "asset_id", "asset_type", "issuer", "owner", "from", "to", "amount", "metadata_hash",
            "fund_id", "lp", "fund_manager", "share_units", "subscription_amount_hkd",
            "portfolio_company", "equity_units", "investment_amount_hkd",
            "compute_project", "beneficiary", "compute_units", "revenue_amount_hkd", "revenue_period", "operator",
            "rights_mapping_id", "legal_document_hash", "oracle_attestation_id", "attestation_hash",
        ):
            if key in body and key not in constraints:
                constraints[key] = body[key]
        if intent == "issue_asset":
            constraints.setdefault("asset_type", "demo_rwa")
            constraints.setdefault("issuer", body.get("requester", "issuer"))
            constraints.setdefault("metadata_hash", sha256_json({"asset_id": constraints.get("asset_id"), "created_at": now_iso()}))
        elif intent == "subscribe_fund_share":
            constraints.setdefault("asset_type", "FundShareToken")
            constraints.setdefault("fund_id", "HK_PE_FUND_I")
            constraints.setdefault("fund_manager", "issuer_A")
            constraints.setdefault("issuer", constraints.get("fund_manager"))
            constraints.setdefault("owner", constraints.get("lp"))
            constraints.setdefault("amount", constraints.get("share_units"))
            constraints.setdefault("metadata_hash", sha256_json({"fund_id": constraints.get("fund_id"), "lp": constraints.get("lp")}))
            constraints.setdefault("rights_mapping_id", "rights-fund-share-hkpe-alice-001")
            constraints.setdefault("legal_document_hash", "hash-legal-hkpe-fund-ppm")
        elif intent == "invest_portfolio_equity":
            constraints.setdefault("asset_type", "PortfolioEquityRWA")
            constraints.setdefault("fund_id", "HK_PE_FUND_I")
            constraints.setdefault("fund_manager", "issuer_A")
            constraints.setdefault("issuer", constraints.get("fund_manager"))
            constraints.setdefault("owner", constraints.get("fund_id"))
            constraints.setdefault("amount", constraints.get("equity_units"))
            constraints.setdefault("metadata_hash", sha256_json({"fund_id": constraints.get("fund_id"), "company": constraints.get("portfolio_company")}))
            constraints.setdefault("rights_mapping_id", "rights-portfolio-equity-aicomp-001")
            constraints.setdefault("legal_document_hash", "hash-legal-aicomp-investment")
        elif intent == "record_compute_revenue":
            constraints.setdefault("asset_type", "ComputePowerToken")
            constraints.setdefault("operator", body.get("requester", "custodian_A"))
            constraints.setdefault("issuer", constraints.get("operator"))
            constraints.setdefault("owner", constraints.get("beneficiary"))
            constraints.setdefault("amount", constraints.get("compute_units"))
            constraints.setdefault("metadata_hash", sha256_json({"project": constraints.get("compute_project"), "beneficiary": constraints.get("beneficiary")}))
            constraints.setdefault("rights_mapping_id", "rights-compute-token-aicomp-001")
            constraints.setdefault("legal_document_hash", "hash-legal-compute-revenue-attestation")
            constraints.setdefault("oracle_attestation_id", "oracle-compute-aicomp-2026q2")
            constraints.setdefault("attestation_hash", constraints.get("metadata_hash"))
        if body.get("zkp"):
            constraints["_zkp"] = body["zkp"]
        return constraints


class App:
    def __init__(self, db_path: str) -> None:
        self.store = Store(db_path)
        self.chain_adapter = build_chain_adapter(self.store)
        self.orchestrator = Orchestrator(self.store, self.chain_adapter)
        self.task_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = TaskWorker(self.store, self.orchestrator, self.stop_event)
        self.worker.start()

    def close(self) -> None:
        self.stop_event.set()
        self.worker.join(timeout=2)


class TaskWorker(threading.Thread):
    def __init__(self, store: Store, orchestrator: Orchestrator, stop_event: threading.Event) -> None:
        super().__init__(daemon=True)
        self.store = store
        self.orchestrator = orchestrator
        self.stop_event = stop_event

    def run(self) -> None:
        while not self.stop_event.is_set():
            item = self.store.claim_next_task()
            if not item:
                self.stop_event.wait(0.15)
                continue
            task_id = item["task_id"]
            try:
                self.orchestrator.execute(task_id)
                self.store.mark_queue_done(task_id)
            except Exception as exc:
                self.store.mark_queue_failed(task_id, str(exc))


def make_handler(app: App):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "AgenticMVP/0.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))

        def end_headers(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Content-Type, Idempotency-Key, X-Request-Signature, Authorization",
            )
            super().end_headers()

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self.end_headers()

        def do_HEAD(self) -> None:
            try:
                self._handle_head()
            except Exception as exc:
                self.send_response(500)
                self.send_header("X-Error", exc.__class__.__name__)
                self.end_headers()

        def do_GET(self) -> None:
            try:
                self._handle_get()
            except Exception as exc:
                self._json(500, {"code": exc.__class__.__name__, "message": str(exc)})

        def do_POST(self) -> None:
            try:
                self._handle_post()
            except ValueError as exc:
                self._json(400, {"code": "bad_request", "message": str(exc)})
            except Exception as exc:
                self._json(500, {"code": exc.__class__.__name__, "message": str(exc)})

        def _handle_head(self) -> None:
            path = urlparse(self.path).path
            if self._serve_static(path, head_only=True):
                return
            if path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def _handle_get(self) -> None:
            path = urlparse(self.path).path
            if self._serve_static(path):
                return

            if path == "/health":
                self._json(200, {"status": "ok", "time": now_iso()})
                return

            if path == "/institutions":
                self._json(200, {"institutions": app.store.list_institutions()})
                return

            if path == "/users":
                self._json(200, {"users": app.store.list_users()})
                return

            if path == "/compliance/licenses":
                self._json(200, {"licensed_institutions": app.store.list_licensed_institutions()})
                return

            if path == "/compliance/kyc-aml":
                self._json(200, {"kyc_aml_profiles": app.store.list_kyc_aml_profiles()})
                return

            if path == "/legal/documents":
                self._json(200, {"legal_documents": app.store.list_legal_documents()})
                return

            if path == "/legal/rights":
                self._json(200, {"rights_mappings": app.store.list_rights_mappings()})
                return

            if path == "/custody/wallets":
                self._json(200, {"wallets": app.store.list_custody_wallets()})
                return

            if path == "/custody/signatures":
                self._json(200, {"signature_requests": app.store.list_signature_requests()})
                return

            if path == "/oracle/attestations":
                self._json(200, {"oracle_attestations": app.store.list_oracle_attestations()})
                return

            if path == "/queue/status":
                self._json(200, app.store.queue_stats())
                return

            if path == "/chain/status":
                self._json(
                    200,
                    {
                        "adapter": app.chain_adapter.adapter_name,
                        "mode": "mock" if app.chain_adapter.adapter_name == "mock" else "external-http",
                    },
                )
                return

            match = re.fullmatch(r"/agent/tasks/([^/]+)", path)
            if match:
                task = app.store.get_task(match.group(1))
                self._json(200, task) if task else self._json(404, {"code": "not_found", "message": "task not found"})
                return

            match = re.fullmatch(r"/agent/tasks/([^/]+)/audit", path)
            if match:
                self._json(200, app.store.audit_for_task(match.group(1)))
                return

            match = re.fullmatch(r"/assets/([^/]+)", path)
            if match:
                asset = app.store.get_asset(match.group(1))
                self._json(200, asset) if asset else self._json(404, {"code": "not_found", "message": "asset not found"})
                return

            match = re.fullmatch(r"/legal/rights/([^/]+)", path)
            if match:
                mapping = app.store.get_rights_mapping(asset_id=match.group(1))
                self._json(200, mapping) if mapping else self._json(404, {"code": "not_found", "message": "rights mapping not found"})
                return

            match = re.fullmatch(r"/transactions/([^/]+)", path)
            if match:
                tx = app.store.get_transaction(match.group(1))
                self._json(200, tx) if tx else self._json(404, {"code": "not_found", "message": "transaction not found"})
                return

            match = re.fullmatch(r"/audit/assets/([^/]+)", path)
            if match:
                self._json(200, app.store.audit_for_asset(match.group(1)))
                return

            self._json(404, {"code": "not_found", "message": f"unknown path: {path}"})

        def _serve_static(self, path: str, head_only: bool = False) -> bool:
            static_files = {
                "/": "index.html",
                "/index.html": "index.html",
                "/styles.css": "styles.css",
                "/app.js": "app.js",
            }
            filename = static_files.get(path)
            if not filename:
                return False
            full_path = os.path.abspath(os.path.join(STATIC_ROOT, filename))
            static_root = os.path.abspath(STATIC_ROOT)
            if not full_path.startswith(static_root + os.sep):
                self._json(403, {"code": "forbidden", "message": "invalid static path"})
                return True
            if not os.path.exists(full_path):
                self._json(404, {"code": "not_found", "message": "static file not found"})
                return True
            with open(full_path, "rb") as fh:
                raw = fh.read()
            content_type = mimetypes.guess_type(full_path)[0] or "application/octet-stream"
            if filename.endswith(".js"):
                content_type = "text/javascript"
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if not head_only:
                self.wfile.write(raw)
            return True

        def _handle_post(self) -> None:
            path = urlparse(self.path).path
            body = parse_json_body(self)
            if path == "/admin/reset":
                app.store.reset()
                self._json(200, {"status": "reset"})
                return

            if path == "/institutions":
                self._json(201, app.store.create_institution(body))
                return

            if path == "/users":
                self._json(201, app.store.create_user(body))
                return

            if path == "/agent/tasks":
                task = app.orchestrator.create_task(body, self.headers.get("Idempotency-Key"))
                self._json(202, task)
                return

            if path == "/assets/issue":
                task = app.orchestrator.create_task(
                    {
                        **body,
                        "intent": "issue_asset",
                        "constraints": {
                            "asset_id": body.get("asset_id"),
                            "asset_type": body.get("asset_type", "demo_rwa"),
                            "issuer": body.get("issuer", body.get("requester")),
                            "owner": body.get("owner"),
                            "amount": body.get("amount"),
                            "metadata_hash": body.get("metadata_hash"),
                        },
                    },
                    self.headers.get("Idempotency-Key"),
                )
                self._json(202, task)
                return

            if path == "/assets/transfer":
                task = app.orchestrator.create_task(
                    {
                        **body,
                        "intent": "transfer_asset",
                        "constraints": {
                            "asset_id": body.get("asset_id"),
                            "from": body.get("from"),
                            "to": body.get("to"),
                            "amount": body.get("amount"),
                        },
                    },
                    self.headers.get("Idempotency-Key"),
                )
                self._json(202, task)
                return

            self._json(404, {"code": "not_found", "message": f"unknown path: {path}"})

        def _json(self, status: int, payload: Any) -> None:
            raw = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return Handler


def serve(host: str, port: int, db_path: str) -> None:
    app = App(db_path)
    handler = make_handler(app)
    server = http.server.ThreadingHTTPServer((host, port), handler)
    print(f"Agentic MVP listening on http://{host}:{port}")
    print(f"SQLite database: {db_path}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default=DEFAULT_DB)
    args = parser.parse_args()
    serve(args.host, args.port, args.db)


if __name__ == "__main__":
    main()
