"""Authorized import of local owner exports and evidence-linked timelines.

This module copies already-created local exports.  It does not access source
systems, acquire credentials, image devices, or establish legal authenticity.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Mapping

from . import __version__

DEFAULT_MAX_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 100_000
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CASE = re.compile(r"^case_[0-9a-f]{32}$")
_SOURCE = re.compile(r"^src_[0-9a-f]{32}$")
_COLLECTOR = re.compile(r"^col_[0-9a-f]{32}$")
_OPAQUE = re.compile(r"^opaque:[0-9a-f]{32}$")
_EVIDENCE = re.compile(r"^evd_[0-9a-f]{32}$")
_EVENT = re.compile(r"^evt_[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HASH_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


class ForensicError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _utc(value: Any, code: str, *, now: datetime | None = None) -> tuple[str, datetime]:
    if not isinstance(value, str) or len(value) > 64:
        raise ForensicError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        raise ForensicError(code) from None
    if parsed.tzinfo is None:
        raise ForensicError(code)
    parsed = parsed.astimezone(timezone.utc)
    if parsed > (now or datetime.now(timezone.utc)):
        raise ForensicError(code)
    return parsed.isoformat().replace("+00:00", "Z"), parsed


def _future_utc(value: Any, code: str, now: datetime) -> tuple[str, datetime]:
    text, parsed = _utc(value, code, now=datetime.max.replace(tzinfo=timezone.utc))
    if parsed <= now:
        raise ForensicError(code)
    return text, parsed


def _now(now: datetime | None = None) -> tuple[str, datetime]:
    if now is not None and now.tzinfo is None:
        raise ForensicError("TIME_INVALID")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return current.isoformat().replace("+00:00", "Z"), current


def _ref(value: Any, code: str, pattern: re.Pattern[str] = _OPAQUE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ForensicError(code)
    return value


def _identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ForensicError(code)
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_json(source: str | Path | Mapping[str, Any], code: str, *, max_bytes: int = 32 * 1024 * 1024) -> dict[str, Any]:
    if isinstance(source, Mapping):
        return json.loads(json.dumps(source))
    path = Path(source)
    try:
        value = json.loads(_stable_bytes(path,max_bytes,code).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ForensicError(code) from None
    if not isinstance(value, dict):
        raise ForensicError(code)
    return value


def _depth(value: Any, level: int = 0) -> int:
    if level > 32:
        raise ForensicError("JSON_TOO_DEEP")
    if isinstance(value, dict):
        return max([level] + [_depth(item, level + 1) for item in value.values()])
    if isinstance(value, list):
        return max([level] + [_depth(item, level + 1) for item in value])
    return level


def load_strict_json(path: str | Path, *, max_bytes: int = 1024 * 1024) -> dict[str, Any]:
    source = Path(path)
    if type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024:
        raise ForensicError("JSON_LIMIT_EXCEEDED")
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        answer: dict[str, Any] = {}
        for key, value in rows:
            if key in answer:
                raise ForensicError("JSON_DUPLICATE_KEY")
            answer[key] = value
        return answer
    try:
        value = json.loads(_stable_bytes(source,max_bytes,"JSON_INVALID").decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ForensicError("JSON_NONFINITE")))
        _depth(value)
    except ForensicError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise ForensicError("JSON_INVALID") from None
    if not isinstance(value, dict):
        raise ForensicError("JSON_INVALID")
    return value


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _no_reparse_chain(path: Path, code: str) -> None:
    absolute = path.absolute()
    for parent in (absolute, *absolute.parents):
        if parent.exists() and _is_reparse(parent):
            raise ForensicError(code)


def _safe_existing_file(path: Path, code: str) -> os.stat_result:
    _no_reparse_chain(path, code)
    try:
        before = path.stat()
    except OSError:
        raise ForensicError(code) from None
    if not stat.S_ISREG(before.st_mode):
        raise ForensicError(code)
    return before


def _stable_bytes(path: Path, maximum: int, code: str) -> bytes:
    before=_safe_existing_file(path,code)
    if before.st_size>maximum: raise ForensicError(code)
    flags=os.O_RDONLY|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)
    try:
        descriptor=os.open(path,flags)
        try:
            opened=os.fstat(descriptor); chunks=[]; total=0
            while True:
                chunk=os.read(descriptor,min(1024*1024,maximum-total+1))
                if not chunk: break
                total+=len(chunk)
                if total>maximum: raise ForensicError(code)
                chunks.append(chunk)
            after_fd=os.fstat(descriptor)
        finally: os.close(descriptor)
        after_path=_safe_existing_file(path,code)
    except ForensicError: raise
    except OSError: raise ForensicError(code) from None
    signature=lambda row:(row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns)
    if any(signature(before)!=signature(row) for row in (opened,after_fd,after_path)): raise ForensicError(code)
    return b"".join(chunks)


def _stable_hash(path: Path, maximum: int, code: str) -> tuple[int, str]:
    before=_safe_existing_file(path,code)
    if before.st_size>maximum: raise ForensicError(code)
    flags=os.O_RDONLY|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)
    digest=hashlib.sha256(); total=0
    try:
        descriptor=os.open(path,flags)
        try:
            opened=os.fstat(descriptor)
            while True:
                chunk=os.read(descriptor,1024*1024)
                if not chunk: break
                total+=len(chunk)
                if total>maximum: raise ForensicError(code)
                digest.update(chunk)
            after_fd=os.fstat(descriptor)
        finally: os.close(descriptor)
        after_path=_safe_existing_file(path,code)
    except ForensicError: raise
    except OSError: raise ForensicError(code) from None
    signature=lambda row:(row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns)
    if any(signature(before)!=signature(row) for row in (opened,after_fd,after_path)): raise ForensicError(code)
    return total,digest.hexdigest()


def _safe_directory(path: Path, code: str, *, create: bool = False) -> Path:
    if create:
        _no_reparse_chain(path.parent, code)
        try:
            path.mkdir(mode=0o700, parents=False, exist_ok=False)
        except OSError:
            raise ForensicError(code) from None
    _no_reparse_chain(path, code)
    if not path.is_dir():
        raise ForensicError(code)
    return path.absolute()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise ForensicError("OUTPUT_EXISTS")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with open(temporary, "x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except ForensicError:
        raise
    except OSError:
        raise ForensicError("ATOMIC_WRITE_FAILED") from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def load_case(source: str | Path | Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    case = _load_json(source, "CASE_INVALID")
    required = {"schema_version", "case_id", "purpose_ref", "retention_until", "authorization", "collectors", "allowed_sources"}
    if set(case) != required or case.get("schema_version") != "1.0":
        raise ForensicError("CASE_INVALID")
    case_id = _ref(case.get("case_id"), "CASE_INVALID", _CASE)
    _ref(case.get("purpose_ref"), "CASE_INVALID")
    _, current = _now(now)
    _future_utc(case.get("retention_until"), "RETENTION_EXPIRED", current)
    authorization = case.get("authorization")
    if not isinstance(authorization, dict) or set(authorization) != {"authorization_ref", "valid_from", "expires_at", "revoked"}:
        raise ForensicError("CASE_INVALID")
    _ref(authorization.get("authorization_ref"), "CASE_INVALID")
    _, valid_from = _utc(authorization.get("valid_from"), "AUTHORIZATION_INVALID", now=current)
    _, expires = _future_utc(authorization.get("expires_at"), "AUTHORIZATION_EXPIRED", current)
    if type(authorization.get("revoked")) is not bool or authorization["revoked"]:
        raise ForensicError("AUTHORIZATION_REVOKED")
    if not valid_from <= current < expires:
        raise ForensicError("AUTHORIZATION_INACTIVE")
    collectors = case.get("collectors")
    if not isinstance(collectors, list) or not 1 <= len(collectors) <= 128:
        raise ForensicError("CASE_INVALID")
    collector_ids: set[str] = set()
    for row in collectors:
        if not isinstance(row, dict) or set(row) != {"collector_id", "tool", "version", "read_only"}:
            raise ForensicError("CASE_INVALID")
        collector_id = _ref(row.get("collector_id"), "CASE_INVALID", _COLLECTOR)
        if collector_id in collector_ids or row.get("read_only") is not True:
            raise ForensicError("CASE_INVALID")
        collector_ids.add(collector_id)
        for key in ("tool", "version"):
            if not isinstance(row.get(key), str) or not 1 <= len(row[key]) <= 128:
                raise ForensicError("CASE_INVALID")
    sources = case.get("allowed_sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 512:
        raise ForensicError("CASE_INVALID")
    source_ids: set[str] = set()
    for row in sources:
        if not isinstance(row, dict) or set(row) != {"source_id", "source_type", "collector_id", "source_provenance_ref", "authorization_ref"}:
            raise ForensicError("CASE_INVALID")
        source_id = _ref(row.get("source_id"), "CASE_INVALID", _SOURCE)
        if source_id in source_ids or row.get("collector_id") not in collector_ids:
            raise ForensicError("CASE_INVALID")
        source_ids.add(source_id)
        if row.get("source_type") != "normalized_event_jsonl":
            raise ForensicError("SOURCE_TYPE_UNSUPPORTED")
        _ref(row.get("source_provenance_ref"), "CASE_INVALID")
        if row.get("authorization_ref") != authorization["authorization_ref"]:
            raise ForensicError("AUTHORIZATION_MISMATCH")
    case["case_id"] = case_id
    return case


def acquire_local_export(case: Mapping[str, Any], source_id: str, export_path: str | Path,
                         evidence_dir: str | Path, *, now: datetime | None = None,
                         max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    case = load_case(case, now=now)
    started_at, started_dt = _now(now)
    if type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024 * 1024:
        raise ForensicError("FILE_LIMIT_INVALID")
    source = next((row for row in case["allowed_sources"] if row["source_id"] == source_id), None)
    if source is None:
        raise ForensicError("SOURCE_NOT_ALLOWED")
    collector = next(row for row in case["collectors"] if row["collector_id"] == source["collector_id"])
    original = Path(export_path)
    before = _safe_existing_file(original, "SOURCE_UNSAFE")
    if before.st_size > max_bytes:
        raise ForensicError("FILE_LIMIT_EXCEEDED")
    root = _safe_directory(Path(evidence_dir), "EVIDENCE_DIRECTORY_UNSAFE")
    evidence_id = "evd_" + secrets.token_hex(16)
    package = root / evidence_id
    _safe_directory(package, "EVIDENCE_DIRECTORY_UNSAFE", create=True)
    artifact = package / "artifact.bin"
    temporary = package / ".artifact.tmp"
    digest = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(original, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                raise ForensicError("SOURCE_CHANGED")
            with os.fdopen(descriptor, "rb", closefd=False) as source_stream, open(temporary, "xb") as target:
                while True:
                    chunk = source_stream.read(min(1024 * 1024, max_bytes - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ForensicError("FILE_LIMIT_EXCEEDED")
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            after_fd = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = _safe_existing_file(original, "SOURCE_CHANGED")
        signature = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
        if signature(before) != signature(after_fd) or signature(before) != signature(after_path):
            raise ForensicError("SOURCE_CHANGED")
        os.replace(temporary, artifact)
        ended_at, _ = _now(max(started_dt, datetime.now(timezone.utc)))
        manifest = {
            "schema_version": "1.0", "case_id": case["case_id"], "evidence_id": evidence_id,
            "source_id": source_id, "source_type": source["source_type"],
            "artifact_relpath": f"{evidence_id}/artifact.bin", "sha256": digest.hexdigest(), "bytes": total,
            "collection_started_at": started_at, "collection_ended_at": ended_at,
            "collector_id": collector["collector_id"], "collector_tool": collector["tool"],
            "collector_version": collector["version"], "su_detect_version": __version__,
            "source_provenance_ref": source["source_provenance_ref"],
            "authorization_ref": source["authorization_ref"], "purpose_ref": case["purpose_ref"],
            "collection_method": "local_export_atomic_copy", "source_mutation": "not_requested",
            "authenticity_limit": "hash_detects_later_change_only; source authenticity and lawful custody are not guaranteed",
        }
        _atomic_json(package / "manifest.json", manifest)
    except ForensicError:
        for created in (temporary, artifact, package / "manifest.json"):
            try: created.unlink(missing_ok=True)
            except OSError: pass
        try: package.rmdir()
        except OSError: pass
        raise
    except OSError:
        for created in (temporary, artifact, package / "manifest.json"):
            try: created.unlink(missing_ok=True)
            except OSError: pass
        try: package.rmdir()
        except OSError: pass
        raise ForensicError("ACQUISITION_FAILED") from None
    return {"status": "ACQUIRED", "case_id": case["case_id"], "evidence_id": evidence_id,
            "sha256": digest.hexdigest(), "bytes": total, "manifest_ref": f"{evidence_id}/manifest.json"}


def verify_manifest(manifest_path: str | Path, *, evidence_dir: str | Path | None = None) -> dict[str, Any]:
    path = Path(manifest_path)
    manifest = _load_json(path, "MANIFEST_INVALID")
    required = {"schema_version", "case_id", "evidence_id", "source_id", "source_type", "artifact_relpath", "sha256", "bytes",
        "collection_started_at", "collection_ended_at", "collector_id", "collector_tool", "collector_version", "su_detect_version",
        "source_provenance_ref", "authorization_ref", "purpose_ref", "collection_method", "source_mutation", "authenticity_limit"}
    if set(manifest) != required or manifest.get("schema_version") != "1.0":
        raise ForensicError("MANIFEST_INVALID")
    evidence_id = _ref(manifest.get("evidence_id"), "MANIFEST_INVALID", _EVIDENCE)
    _ref(manifest.get("case_id"), "MANIFEST_INVALID", _CASE)
    _ref(manifest.get("source_id"),"MANIFEST_INVALID",_SOURCE)
    _ref(manifest.get("collector_id"),"MANIFEST_INVALID",_COLLECTOR)
    for key in ("source_provenance_ref","authorization_ref","purpose_ref"): _ref(manifest.get(key),"MANIFEST_INVALID")
    for key in ("collector_tool","collector_version","su_detect_version"):
        if not isinstance(manifest.get(key),str) or not 1<=len(manifest[key])<=128: raise ForensicError("MANIFEST_INVALID")
    if (manifest.get("source_type")!="normalized_event_jsonl" or manifest.get("collection_method")!="local_export_atomic_copy"
            or manifest.get("source_mutation")!="not_requested" or not isinstance(manifest.get("authenticity_limit"),str)):
        raise ForensicError("MANIFEST_INVALID")
    if type(manifest.get("bytes")) is not int or manifest["bytes"] < 0 or not isinstance(manifest.get("sha256"), str) or not _SHA256.fullmatch(manifest["sha256"]):
        raise ForensicError("MANIFEST_INVALID")
    started, started_dt = _utc(manifest.get("collection_started_at"), "MANIFEST_INVALID")
    ended, ended_dt = _utc(manifest.get("collection_ended_at"), "MANIFEST_INVALID")
    if ended_dt < started_dt:
        raise ForensicError("MANIFEST_INVALID")
    rel = Path(str(manifest.get("artifact_relpath", "")))
    if rel.is_absolute() or ".." in rel.parts or rel.as_posix() != f"{evidence_id}/artifact.bin":
        raise ForensicError("MANIFEST_INVALID")
    root = _safe_directory(Path(evidence_dir) if evidence_dir is not None else path.parent.parent, "EVIDENCE_DIRECTORY_UNSAFE")
    artifact = root / rel; current = _safe_existing_file(artifact, "ARTIFACT_MISSING")
    if current.st_size != manifest["bytes"]: raise ForensicError("ARTIFACT_SIZE_MISMATCH")
    total,digest=_stable_hash(artifact,manifest["bytes"]+1,"ARTIFACT_CHANGED_DURING_VERIFY")
    if total!=manifest["bytes"]: raise ForensicError("ARTIFACT_SIZE_MISMATCH")
    if digest != manifest["sha256"]:
        raise ForensicError("ARTIFACT_HASH_MISMATCH")
    return {"status": "VERIFIED", "case_id": manifest["case_id"], "evidence_id": evidence_id,
            "authorization_checked":False,"verification_scope":"historical artifact integrity only"}


def verify_custody_chain(chain_path: str | Path, *, expected_head: str | None = None) -> dict[str, Any]:
    path = Path(chain_path)
    _safe_existing_file(path, "CUSTODY_CHAIN_INVALID")
    previous = "0" * 64
    seen: set[str] = set()
    count = 0
    case_id: str | None = None
    try:
        with path.open("r", encoding="utf-8") as stream:
            while True:
                line=stream.readline(64*1024+1)
                if not line: break
                count += 1
                if count > MAX_EVENTS or len(line) > 64 * 1024 or not line.endswith("\n"):
                    raise ForensicError("CUSTODY_CHAIN_INVALID")
                row = json.loads(line)
                if (not isinstance(row, dict) or type(row.get("sequence")) is not int
                        or row.get("sequence") != count or row.get("previous_hash") != previous):
                    raise ForensicError("CUSTODY_SEQUENCE_INVALID")
                required={"schema_version","case_id","sequence","previous_hash","event_id","event_type","actor_ref","evidence_id","occurred_at","action_ref","event_hash"}
                if set(row)!=required or row.get("schema_version")!="1.0": raise ForensicError("CUSTODY_EVENT_INVALID")
                row_case=_ref(row.get("case_id"),"CUSTODY_EVENT_INVALID",_CASE)
                if case_id is None: case_id=row_case
                elif row_case!=case_id: raise ForensicError("CUSTODY_CASE_MISMATCH")
                _ref(row.get("event_id"),"CUSTODY_EVENT_INVALID",_EVENT)
                _identifier(row.get("event_type"),"CUSTODY_EVENT_INVALID")
                _ref(row.get("actor_ref"),"CUSTODY_EVENT_INVALID")
                _ref(row.get("evidence_id"),"CUSTODY_EVENT_INVALID",_EVIDENCE)
                _ref(row.get("action_ref"),"CUSTODY_EVENT_INVALID")
                _utc(row.get("occurred_at"),"CUSTODY_EVENT_INVALID")
                event_hash = row.get("event_hash")
                if not isinstance(event_hash, str) or not _SHA256.fullmatch(event_hash):
                    raise ForensicError("CUSTODY_HASH_INVALID")
                body = dict(row); body.pop("event_hash")
                if hashlib.sha256(_canonical(body)).hexdigest() != event_hash:
                    raise ForensicError("CUSTODY_HASH_INVALID")
                event_id = _ref(row.get("event_id"), "CUSTODY_EVENT_INVALID", _EVENT)
                if event_id in seen:
                    raise ForensicError("CUSTODY_DUPLICATE_EVENT")
                seen.add(event_id); previous = event_hash
    except ForensicError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ForensicError("CUSTODY_CHAIN_INVALID") from None
    if expected_head is not None and (not _SHA256.fullmatch(expected_head) or previous != expected_head):
        raise ForensicError("CUSTODY_HEAD_MISMATCH")
    return {"status": "VERIFIED", "case_id": case_id, "events": count, "head_hash": previous,
            "truncation_limit": "tail truncation or full rehash is detectable only against an independently retained expected_head"}


def append_custody_event(case: Mapping[str, Any], chain_path: str | Path, event: Mapping[str, Any],
                         *, now: datetime | None = None, expected_head: str | None = None,
                         evidence_dir: str | Path | None = None) -> dict[str, Any]:
    case = load_case(case, now=now)
    path = Path(chain_path)
    _no_reparse_chain(path.parent, "CUSTODY_CHAIN_INVALID")
    if not path.parent.is_dir():
        raise ForensicError("CUSTODY_CHAIN_INVALID")
    required = {"event_id", "event_type", "actor_ref", "evidence_id", "occurred_at", "action_ref"}
    if not isinstance(event, Mapping) or set(event) != required:
        raise ForensicError("CUSTODY_EVENT_INVALID")
    event_id = _ref(event.get("event_id"), "CUSTODY_EVENT_INVALID", _EVENT)
    _identifier(event.get("event_type"), "CUSTODY_EVENT_INVALID")
    _ref(event.get("actor_ref"), "CUSTODY_EVENT_INVALID")
    evidence_id=_ref(event.get("evidence_id"), "CUSTODY_EVENT_INVALID", _EVIDENCE)
    evidence_verified=False
    if evidence_dir is not None:
        root=_safe_directory(Path(evidence_dir),"EVIDENCE_DIRECTORY_UNSAFE")
        verified=verify_manifest(root/evidence_id/"manifest.json",evidence_dir=root)
        if verified["case_id"]!=case["case_id"]: raise ForensicError("EVIDENCE_CASE_MISMATCH")
        evidence_verified=True
    _ref(event.get("action_ref"), "CUSTODY_EVENT_INVALID")
    occurred_at, _ = _utc(event.get("occurred_at"), "CUSTODY_EVENT_INVALID")
    lock=path.with_name(path.name+".lock")
    try:
        lock_fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    except OSError:
        raise ForensicError("CUSTODY_LOCKED") from None
    try:
        os.close(lock_fd)
        if path.exists(): state=verify_custody_chain(path,expected_head=expected_head)
        else:
            if expected_head not in (None,"0"*64): raise ForensicError("CUSTODY_HEAD_MISMATCH")
            state={"case_id":None,"events":0,"head_hash":"0"*64}
        if state.get("case_id") not in (None,case["case_id"]): raise ForensicError("CUSTODY_CASE_MISMATCH")
        with path.open("r",encoding="utf-8") if path.exists() else open(os.devnull,"r") as stream:
            while True:
                line=stream.readline(64*1024+1)
                if not line: break
                if json.loads(line).get("event_id")==event_id: raise ForensicError("CUSTODY_DUPLICATE_EVENT")
        row={"schema_version":"1.0","case_id":case["case_id"],"sequence":state["events"]+1,
             "previous_hash":state["head_hash"],**dict(event),"occurred_at":occurred_at}
        row["event_hash"]=hashlib.sha256(_canonical(row)).hexdigest()
        flags=os.O_APPEND|os.O_CREAT|os.O_WRONLY|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)
        descriptor=os.open(path,flags,0o600)
        with os.fdopen(descriptor,"ab") as stream:
            stream.write(_canonical(row)+b"\n"); stream.flush(); os.fsync(stream.fileno())
    except ForensicError: raise
    except (OSError,UnicodeError,json.JSONDecodeError): raise ForensicError("CUSTODY_APPEND_FAILED") from None
    finally:
        try: lock.unlink(missing_ok=True)
        except OSError: pass
    return {"status": "APPENDED", "case_id": case["case_id"], "event_id": event_id,
            "events": row["sequence"], "head_hash": row["event_hash"],
            "evidence_verified":evidence_verified,
            "evidence_limit":None if evidence_verified else "evidence reference was not verified against an artifact manifest"}


def _timeline_event(row: Any, case: Mapping[str, Any], evidence_dir: Path, now: datetime) -> dict[str, Any]:
    required = {"event_id", "source_id", "evidence_id", "event_time", "ingest_time", "clock_uncertainty_ms",
                "actor_ref", "asset_ref", "source_record_ref", "activity"}
    if not isinstance(row, dict) or set(row) != required:
        raise ForensicError("TIMELINE_EVENT_INVALID")
    event_id = _ref(row.get("event_id"), "TIMELINE_EVENT_INVALID", _EVENT)
    sources = {item["source_id"] for item in case["allowed_sources"]}
    if row.get("source_id") not in sources:
        raise ForensicError("SOURCE_NOT_ALLOWED")
    evidence_id = _ref(row.get("evidence_id"), "TIMELINE_EVENT_INVALID", _EVIDENCE)
    verified = verify_manifest(evidence_dir / evidence_id / "manifest.json", evidence_dir=evidence_dir)
    if verified["case_id"] != case["case_id"]:
        raise ForensicError("EVIDENCE_CASE_MISMATCH")
    manifest = _load_json(evidence_dir / evidence_id / "manifest.json", "MANIFEST_INVALID")
    if manifest["source_id"] != row["source_id"]:
        raise ForensicError("EVIDENCE_SOURCE_MISMATCH")
    event_time, _ = _utc(row.get("event_time"), "TIMELINE_TIME_INVALID", now=now)
    ingest_time, _ = _utc(row.get("ingest_time"), "TIMELINE_TIME_INVALID", now=now)
    uncertainty = row.get("clock_uncertainty_ms")
    if type(uncertainty) is not int or not 0 <= uncertainty <= 86_400_000:
        raise ForensicError("TIMELINE_TIME_INVALID")
    _ref(row.get("actor_ref"), "TIMELINE_EVENT_INVALID")
    _ref(row.get("asset_ref"), "TIMELINE_EVENT_INVALID")
    _ref(row.get("source_record_ref"), "TIMELINE_EVENT_INVALID", _HASH_REF)
    activity = _identifier(row.get("activity"), "TIMELINE_EVENT_INVALID")
    return {**row, "event_id": event_id, "evidence_id": evidence_id, "event_time": event_time,
            "ingest_time": ingest_time, "activity": activity,
            "interpretation_limit": "event linkage does not establish actor attribution, public access, or exfiltration"}


def _normalized_records(content: bytes, max_events: int) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    required = {"event_id", "event_time", "ingest_time", "clock_uncertainty_ms", "actor_ref", "asset_ref", "activity"}
    try:
        import io
        with io.StringIO(content.decode("utf-8")) as stream:
            index = 0
            while True:
                raw = stream.readline(256 * 1024 + 1)
                if not raw: break
                index += 1
                if index > max_events or len(raw) > 256 * 1024 or not raw.endswith("\n"):
                    raise ForensicError("EVENT_LIMIT_EXCEEDED")
                value = json.loads(raw)
                if not isinstance(value, dict) or set(value) != required:
                    raise ForensicError("SOURCE_RECORD_INVALID")
                reference = "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()
                if reference in records:
                    raise ForensicError("SOURCE_RECORD_DUPLICATE")
                records[reference] = value
    except ForensicError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise ForensicError("SOURCE_RECORD_INVALID") from None
    return records


def _verify_timeline_rows(rows: list[Any], case_id: str, evidence_dir: Path,
                          *, now: datetime, allowed_sources: set[str] | None = None) -> list[dict[str, Any]]:
    seen: set[str] = set(); manifests: dict[str, dict[str, Any]] = {}; records: dict[str, dict[str, dict[str, Any]]] = {}
    answer: list[dict[str, Any]] = []
    for raw in rows:
        if not isinstance(raw, dict): raise ForensicError("TIMELINE_EVENT_INVALID")
        event_id = _ref(raw.get("event_id"), "TIMELINE_EVENT_INVALID", _EVENT)
        if event_id in seen: raise ForensicError("TIMELINE_DUPLICATE_EVENT")
        seen.add(event_id)
        source_id = _ref(raw.get("source_id"), "TIMELINE_EVENT_INVALID", _SOURCE)
        if allowed_sources is not None and source_id not in allowed_sources: raise ForensicError("SOURCE_NOT_ALLOWED")
        evidence_id = _ref(raw.get("evidence_id"), "TIMELINE_EVENT_INVALID", _EVIDENCE)
        if evidence_id not in manifests:
            verify_manifest(evidence_dir/evidence_id/"manifest.json", evidence_dir=evidence_dir)
            manifests[evidence_id] = _load_json(evidence_dir/evidence_id/"manifest.json", "MANIFEST_INVALID")
            manifest=manifests[evidence_id]
            if manifest["bytes"]>DEFAULT_MAX_BYTES: raise ForensicError("TIMELINE_ARTIFACT_LIMIT_EXCEEDED")
            content=_stable_bytes(evidence_dir/evidence_id/"artifact.bin",DEFAULT_MAX_BYTES,"ARTIFACT_CHANGED_DURING_VERIFY")
            if len(content)!=manifest["bytes"] or hashlib.sha256(content).hexdigest()!=manifest["sha256"]:
                raise ForensicError("ARTIFACT_HASH_MISMATCH")
            records[evidence_id] = _normalized_records(content, MAX_EVENTS)
        manifest = manifests[evidence_id]
        if manifest["case_id"] != case_id: raise ForensicError("EVIDENCE_CASE_MISMATCH")
        if manifest["source_id"] != source_id: raise ForensicError("EVIDENCE_SOURCE_MISMATCH")
        ref = _ref(raw.get("source_record_ref"), "TIMELINE_EVENT_INVALID", _HASH_REF)
        original = records[evidence_id].get(ref)
        if original is None: raise ForensicError("SOURCE_RECORD_MISSING")
        event_time = _utc(raw.get("event_time"), "TIMELINE_TIME_INVALID", now=now)[0]
        ingest_time = _utc(raw.get("ingest_time"), "TIMELINE_TIME_INVALID", now=now)[0]
        uncertainty=raw.get("clock_uncertainty_ms")
        if type(uncertainty) is not int or not 0<=uncertainty<=86_400_000: raise ForensicError("TIMELINE_TIME_INVALID")
        for key in ("actor_ref","asset_ref"): _ref(raw.get(key),"TIMELINE_EVENT_INVALID")
        _identifier(raw.get("activity"),"TIMELINE_EVENT_INVALID")
        compared={key:raw[key] for key in ("event_id","clock_uncertainty_ms","actor_ref","asset_ref","activity")}
        expected={key:original[key] for key in compared}
        compared.update(event_time=event_time,ingest_time=ingest_time)
        expected.update(event_time=_utc(original["event_time"],"TIMELINE_TIME_INVALID",now=now)[0],ingest_time=_utc(original["ingest_time"],"TIMELINE_TIME_INVALID",now=now)[0])
        if compared != expected: raise ForensicError("SOURCE_RECORD_MISMATCH")
        answer.append({**raw,"event_time":event_time,"ingest_time":ingest_time,
            "interpretation_limit":"event linkage does not establish actor attribution, public access, or exfiltration"})
    return answer


def build_timeline(case: Mapping[str, Any], event_jsonl: str | Path, evidence_dir: str | Path,
                   output_path: str | Path, *, now: datetime | None = None, max_events: int = MAX_EVENTS) -> dict[str, Any]:
    case = load_case(case, now=now)
    if type(max_events) is not int or not 1 <= max_events <= MAX_EVENTS:
        raise ForensicError("EVENT_LIMIT_INVALID")
    source_path = Path(event_jsonl); _safe_existing_file(source_path, "TIMELINE_INPUT_INVALID")
    root = _safe_directory(Path(evidence_dir), "EVIDENCE_DIRECTORY_UNSAFE")
    _, current = _now(now)
    input_rows=[]
    try:
        with source_path.open("r", encoding="utf-8") as stream:
            while True:
                raw=stream.readline(256*1024+1)
                if not raw: break
                if len(input_rows) >= max_events or len(raw) > 256 * 1024 or not raw.endswith("\n"):
                    raise ForensicError("EVENT_LIMIT_EXCEEDED")
                input_rows.append(json.loads(raw))
    except ForensicError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ForensicError("TIMELINE_INPUT_INVALID") from None
    rows=_verify_timeline_rows(input_rows,case["case_id"],root,now=current,
        allowed_sources={item["source_id"] for item in case["allowed_sources"]})
    rows.sort(key=lambda row: (datetime.fromisoformat(row["event_time"].replace("Z","+00:00")), row["event_id"]))
    content_hash = hashlib.sha256(_canonical(rows)).hexdigest()
    timeline = {"schema_version": "1.0", "case_id": case["case_id"], "created_at": _now(now)[0],
                "events": rows, "events_sha256": content_hash,
                "analysis_limit": "absence of logs is not evidence of no access or exfiltration; correlation is not attribution"}
    output = Path(output_path); _no_reparse_chain(output.parent, "TIMELINE_OUTPUT_INVALID")
    _atomic_json(output, timeline)
    return {"status": "CREATED", "case_id": case["case_id"], "events": len(rows), "sha256": content_hash}


def verify_timeline(path: str | Path, evidence_dir: str | Path) -> dict[str, Any]:
    timeline = _load_json(path, "TIMELINE_INVALID", max_bytes=64*1024*1024)
    if set(timeline) != {"schema_version", "case_id", "created_at", "events", "events_sha256", "analysis_limit"}:
        raise ForensicError("TIMELINE_INVALID")
    rows = timeline.get("events")
    if not isinstance(rows, list) or len(rows) > MAX_EVENTS or hashlib.sha256(_canonical(rows)).hexdigest() != timeline.get("events_sha256"):
        raise ForensicError("TIMELINE_HASH_MISMATCH")
    root = _safe_directory(Path(evidence_dir), "EVIDENCE_DIRECTORY_UNSAFE")
    _,current=_now()
    checked=_verify_timeline_rows(rows,timeline.get("case_id"),root,now=current)
    if checked != rows: raise ForensicError("TIMELINE_NORMALIZATION_MISMATCH")
    if rows != sorted(rows,key=lambda row:(datetime.fromisoformat(row["event_time"].replace("Z","+00:00")),row["event_id"])):
        raise ForensicError("TIMELINE_ORDER_INVALID")
    return {"status": "VERIFIED", "case_id": timeline["case_id"], "events": len(rows), "sha256": timeline["events_sha256"]}
