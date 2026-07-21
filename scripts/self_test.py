#!/usr/bin/env python3
"""Synthetic, zero-dependency safety tests for WeComCracker."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from argparse import Namespace
from pathlib import Path
import sqlite3
import sys
import tempfile


SCRIPT = Path(__file__).with_name("wecomcracker.py")
SPEC = importlib.util.spec_from_file_location("wecomcracker", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not import {SCRIPT}")
vault = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vault
SPEC.loader.exec_module(vault)


def metadata(path: Path) -> tuple[int, int, str]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()


def create_fixture(directory: Path) -> None:
    schemas = {
        "message.db": (
            "CREATE TABLE message_table ("
            "message_id INTEGER, sequence INTEGER, conversation_id TEXT, "
            "sender_id TEXT, content_type INTEGER, send_time INTEGER, content BLOB)"
        ),
        "session.db": (
            "CREATE TABLE conversation_table ("
            "id TEXT, name TEXT, roomname_remark TEXT, last_message_time INTEGER, "
            "last_message_id INTEGER, is_sticked INTEGER)"
        ),
        "user.db": (
            "CREATE TABLE user_table (id TEXT, name TEXT, english_name TEXT)"
        ),
    }
    directory.mkdir(parents=True)
    for name, schema in schemas.items():
        connection = sqlite3.connect(directory / name)
        try:
            connection.execute(schema)
            connection.commit()
        finally:
            connection.close()


def expect_error(error_type: type[Exception], operation) -> None:
    try:
        operation()
    except error_type:
        return
    raise AssertionError(f"Expected {error_type.__name__}")


def main() -> int:
    checks: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="wecomcracker-test-") as raw_root:
        root = Path(raw_root)
        source = root / "account" / "Data"
        create_fixture(source)

        databases = vault.collect_databases(source)
        checks["recognized_core_databases"] = sorted(
            database.relative_path.name for database in databases
        )
        assert checks["recognized_core_databases"] == [
            "message.db",
            "session.db",
            "user.db",
        ]

        fresh_output = root / "snapshot"
        vault.assert_safe_output(source, fresh_output)
        expect_error(ValueError, lambda: vault.assert_safe_output(source, source))
        expect_error(
            ValueError, lambda: vault.assert_safe_output(source, source / "snapshot")
        )
        expect_error(
            ValueError, lambda: vault.assert_safe_output(source, source.parent)
        )
        existing = root / "existing"
        existing.mkdir()
        expect_error(
            FileExistsError, lambda: vault.assert_safe_output(source, existing)
        )
        checks["unsafe_output_paths_rejected"] = True

        db = source / "message.db"
        wal = source / "message.db-wal"
        shm = source / "message.db-shm"
        wal.write_bytes(b"")
        shm.write_bytes(b"synthetic-sidecar-sentinel")
        before = {path.name: metadata(path) for path in (db, wal, shm)}
        assert vault.sqlite_quick_check(db) == "ok"
        after = {path.name: metadata(path) for path in (db, wal, shm)}
        assert before == after
        checks["immutable_query_left_db_wal_shm_unchanged"] = True

        wal.write_bytes(b"non-empty synthetic WAL")
        expect_error(RuntimeError, lambda: vault.sqlite_quick_check(db))
        blocked_output = root / "blocked-snapshot"
        expect_error(
            RuntimeError,
            lambda: vault.decrypt_snapshot(
                Namespace(
                    db_dir=str(source),
                    out_dir=str(blocked_output),
                    base_only=False,
                    timeout=1,
                    verbose=False,
                )
            ),
        )
        assert not blocked_output.exists()
        checks["nonempty_wal_failed_closed"] = True

        assert vault.bounded_positive_int("1") == 1
        assert vault.bounded_positive_int("10000") == 10_000
        expect_error(Exception, lambda: vault.bounded_positive_int("0"))
        expect_error(Exception, lambda: vault.bounded_positive_int("10001"))
        checks["result_limits_enforced"] = "1..10000"

        incomplete = root / "incomplete-snapshot"
        incomplete.mkdir()
        (incomplete / "snapshot_manifest.json").write_text(
            json.dumps(
                {
                    "complete": False,
                    "base_only": True,
                    "wal_processed": False,
                    "ignored_nonempty_wals": [
                        {"relative_path": "message.db-wal", "bytes": 23}
                    ],
                }
            ),
            encoding="utf-8",
        )
        status = vault._snapshot_status(incomplete)
        assert status["complete"] is False
        assert "warning" in status
        assert status["ignored_nonempty_wals"]
        checks["incomplete_snapshot_warning"] = True

        parsed = vault._parse_message_content(
            b"access_token=abcdefghijklmnop https://x.test/?sig=abcdefghijklmnop "
            + b"A" * 80
        )
        assert "abcdefghijklmnop" not in parsed
        assert "A" * 80 not in parsed
        checks["sensitive_text_redaction"] = True

        with vault.WindowsAesCbc() as aes:
            vault.cng_self_test(aes)
        checks["windows_cng_aes_self_test"] = "ok"

    print(json.dumps({"success": True, "checks": checks}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
