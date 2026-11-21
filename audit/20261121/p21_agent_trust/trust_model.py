# -*- coding: utf-8 -*-
"""XLGD Agent Trust Network —— 本地原型（研究件，非产品）。"""
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

NOW = datetime(2026, 11, 19, 10, 0, tzinfo=timezone.utc)
KEYS = {}


def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha(o) -> str:
    return hashlib.sha256(canon(o)).hexdigest()


def sign(obj: dict, key_id: str) -> str:
    return hmac.new(KEYS[key_id].encode(), canon(obj), hashlib.sha256).hexdigest()


# ---------------- WP1 Agent Identity ----------------
@dataclass
class AgentIdentity:
    agent_id: str
    creator: str
    operator: str
    implementer: str
    versions: List[str] = field(default_factory=list)
    key_fingerprint: str = ""
    revoked: bool = False
    revocation_reason: str = ""

    def add_version(self, v: str) -> None:
        """版本变更但身份连续：同一 agent_id，版本追加，不重建身份。"""
        if v not in self.versions:
            self.versions.append(v)

    def check_key(self, presented_fp: str) -> Tuple[bool, str]:
        if self.revoked:
            return False, f"identity revoked: {self.revocation_reason}"
        if presented_fp != self.key_fingerprint:
            return False, "key fingerprint mismatch (impersonation)"
        return True, "ok"


# ---------------- WP2 Behavioral Evidence ----------------
@dataclass
class Evidence:
    ev_id: str
    agent_id: str
    agent_version: str
    source: str          # observed | declared
    producer: str
    payload: dict
    issued_at: datetime
    ttl_days: int
    privacy: str = "redacted"
    mac: str = ""
    key_id: str = ""

    def integrity_ok(self) -> bool:
        body = {k: v for k, v in self.__dict__.items() if k != "mac"}
        body["issued_at"] = self.issued_at.isoformat()
        return hmac.compare_digest(sign(_serialize(body), self.key_id), self.mac)

    def expired(self, now: datetime = NOW) -> bool:
        return now > self.issued_at + timedelta(days=self.ttl_days)

    def matches_version(self, v: str) -> bool:
        return self.agent_version == v


def _serialize(body: dict) -> dict:
    return {k: body[k] for k in sorted(body)}


def make_evidence(ev_id, agent_id, version, source, producer, payload, key_id,
                  issued_at=NOW, ttl_days=90) -> Evidence:
    ev = Evidence(ev_id, agent_id, version, source, producer, payload, issued_at, ttl_days,
                  key_id=key_id)
    body = {k: v for k, v in ev.__dict__.items() if k != "mac"}
    body["issued_at"] = issued_at.isoformat()
    ev.mac = sign(_serialize(body), key_id)
    return ev


# ---------------- WP3 Trust Delegation ----------------
@dataclass
class Delegation:
    deleg_id: str
    frm: str
    to: str
    scope: Set[str]
    depth: int = 1
    max_depth: int = 2
    allow_redelegation: bool = False
    expires_at: Optional[datetime] = None
    revoked: bool = False


class DelegationLedger:
    def __init__(self) -> None:
        self.items: List[Delegation] = []

    def grant(self, d: Delegation) -> None:
        self.items.append(d)

    def effective_scope(self, agent: str) -> Set[str]:
        """从根开始求委托作用域交集。"""
        scopes: Set[str] = set()
        reachable = [d for d in self.items if d.to == agent and not d.revoked]
        for d in reachable:
            if d.frm == "root":
                scopes |= d.scope
            else:
                parent = self.effective_scope(d.frm)
                scopes |= (d.scope & parent)
        return scopes

    def can_act(self, agent: str, requested: Set[str]) -> Tuple[bool, str]:
        eff = self.effective_scope(agent)
        if not eff:
            return False, "no effective delegation"
        missing = requested - eff
        if missing:
            return False, f"scope exceeds delegation: {sorted(missing)}"
        return True, "ok"

    def validate_chain(self, agent: str) -> Tuple[bool, str]:
        chain = [d for d in self.items if d.to == agent and not d.revoked]
        if not chain:
            return False, "no delegation"
        for d in chain:
            if d.depth > d.max_depth:
                return False, "depth exceeds max_depth"
            if d.frm != "root":
                if not any(x.to == d.frm for x in self.items):
                    return False, f"broken chain at {d.frm}"
                if not any(x.allow_redelegation for x in self.items if x.to == d.frm):
                    return False, "re-delegation not allowed"
        return True, "ok"

    def revoke(self, deleg_id: str) -> List[str]:
        """撤销委托并级联到所有下游。"""
        affected = []
        target = next((d for d in self.items if d.deleg_id == deleg_id), None)
        if not target:
            return affected
        target.revoked = True
        affected.append(target.to)
        queue = [target.to]
        while queue:
            cur = queue.pop(0)
            for child in [d for d in self.items if d.frm == cur and not d.revoked]:
                child.revoked = True
                affected.append(child.to)
                queue.append(child.to)
        return affected


# ---------------- WP4 Dynamic Trust ----------------
@dataclass
class TrustSnapshot:
    agent_id: str
    version: str
    identity_ok: bool
    evaluation_score: Optional[float]
    evidence_state: str      # VERIFIED | UNKNOWN | INCOMPLETE | STALE
    authorization: Optional[dict]   # subject/scope/expires_at

    def decision(self, requested_scope: Set[str], now: datetime = NOW) -> Tuple[str, str]:
        """评测分数不参与决策；授权必须独立存在。"""
        if not self.identity_ok:
            return "DENY", "identity not verified"
        if self.evidence_state != "VERIFIED":
            return "DENY", f"evidence {self.evidence_state} (fail-closed)"
        if not self.authorization:
            return "DENY", "NOT_GRANTED (evaluation score does not authorize)"
        a = self.authorization
        if not all(k in a for k in ("subject", "scope", "expires_at")):
            return "DENY", "authorization incomplete"
        if datetime.fromisoformat(a["expires_at"]) <= now:
            return "DENY", "authorization expired"
        if not requested_scope <= set(a["scope"]):
            return "DENY", "scope not granted"
        return "ALLOW", "ok"


# ---------------- WP5 Supply Chain ----------------
@dataclass
class DepNode:
    name: str
    version: str
    source: str           # registry | git | vendored
    compromised: bool = False


class SupplyChain:
    def __init__(self) -> None:
        self.edges: Dict[str, List[DepNode]] = {}

    def add(self, agent: str, dep: DepNode) -> None:
        self.edges.setdefault(agent, []).append(dep)

    def risk(self, agent: str, seen=None) -> Tuple[bool, str]:
        seen = seen or set()
        if agent in seen:
            return False, ""
        seen.add(agent)
        bad = [d.name for d in self.edges.get(agent, []) if d.compromised]
        for d in self.edges.get(agent, []):
            _, msg = self.risk(d.name, seen)
            if msg:
                bad.append(f"{d.name}->{msg}")
        if bad:
            return True, f"{agent}: {bad}"
        return False, ""

    def dependents(self, node: str) -> List[str]:
        """谁依赖 node（反查，用于撤销向上传播）。"""
        out = []
        for agent, deps in self.edges.items():
            for d in deps:
                if d.name == node:
                    out.append(agent)
        return out

    def invalidate(self, node: str) -> int:
        """对象被撤销/污染后，把依赖图中所有同名节点标记为 compromised。"""
        n = 0
        for deps in self.edges.values():
            for d in deps:
                if d.name == node and not d.compromised:
                    d.compromised = True
                    n += 1
        return n


# ---------------- WP6/WP7 Registry + Trust API ----------------
class TrustRegistry:
    def __init__(self) -> None:
        self.agents: Dict[str, AgentIdentity] = {}
        self.evidence: List[Evidence] = []
        self.ledger = DelegationLedger()
        self.chain = SupplyChain()
        self.revocations: List[dict] = []

    # --- API ---
    def resolve(self, agent_id: str) -> Tuple[bool, dict]:
        a = self.agents.get(agent_id)
        if not a:
            return False, {"status": "UNKNOWN"}
        if a.revoked:
            return False, {"status": "REVOKED", "reason": a.revocation_reason}
        return True, {"status": "REGISTERED", "versions": a.versions,
                      "creator": a.creator, "operator": a.operator}

    def query_evidence(self, agent_id: str, version: str) -> dict:
        evs = [e for e in self.evidence if e.agent_id == agent_id]
        if not evs:
            return {"state": "UNKNOWN", "items": []}
        matching = [e for e in evs if e.matches_version(version)]
        if not matching:
            return {"state": "STALE", "items": [e.ev_id for e in evs]}
        if not all(e.integrity_ok() and not e.expired() for e in matching):
            return {"state": "INCOMPLETE", "items": [e.ev_id for e in matching]}
        return {"state": "VERIFIED", "items": [e.ev_id for e in matching]}

    def revoke(self, agent_id: str, reason: str) -> List[str]:
        a = self.agents[agent_id]
        a.revoked = True
        a.revocation_reason = reason
        self.revocations.append({"agent": agent_id, "reason": reason,
                                 "at": NOW.isoformat(), "kind": "IDENTITY"})
        affected = [agent_id]
        affected += self.ledger.revoke_all_from(agent_id)
        self.chain.invalidate(agent_id)
        affected += self.chain.dependents(agent_id)
        return affected


def _revoke_all_from(self: DelegationLedger, agent: str) -> List[str]:
    out = []
    for d in self.items:
        if d.frm == agent and not d.revoked:
            out += self.revoke(d.deleg_id)
    return out


DelegationLedger.revoke_all_from = _revoke_all_from
