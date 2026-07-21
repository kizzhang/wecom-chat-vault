#!/usr/bin/env python3
"""WeComCracker：适用于 Windows 的零第三方依赖企业微信本地聊天快照读取器。

仅使用 Python 标准库和 Windows API。以只读方式打开企业微信源数据库目录；
恢复出的密钥只保留在进程内存中，绝不打印或写入磁盘。使用 SQLite 不可变只读
URI 查询明文快照，确保检查过程不会创建 WAL/SHM 边车文件。
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes as wt
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import struct
import sys
import time
from typing import Iterable, Optional
import uuid
import winreg


if os.name != "nt":
    raise SystemExit("此脚本需要在 Windows 上运行。")


PAGE_SIZE = 4096
SQLITE_HEADER = b"SQLite format 3\x00"
WXSQLITE3_SALT = b"sAlT"

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x0100
PAGE_NOACCESS = 0x0001
READABLE_PAGE_TYPES = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
bcrypt = ctypes.WinDLL("bcrypt", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * MAX_PATH),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wt.BOOL
kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wt.BOOL
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.VirtualQueryEx.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.GetCurrentProcessId.argtypes = []
kernel32.GetCurrentProcessId.restype = wt.DWORD
kernel32.ProcessIdToSessionId.argtypes = [wt.DWORD, ctypes.POINTER(wt.DWORD)]
kernel32.ProcessIdToSessionId.restype = wt.BOOL
shell32.IsUserAnAdmin.argtypes = []
shell32.IsUserAnAdmin.restype = wt.BOOL


bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),
    wt.LPCWSTR,
    wt.LPCWSTR,
    wt.ULONG,
]
bcrypt.BCryptOpenAlgorithmProvider.restype = wt.LONG
bcrypt.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, wt.ULONG]
bcrypt.BCryptCloseAlgorithmProvider.restype = wt.LONG
bcrypt.BCryptSetProperty.argtypes = [
    ctypes.c_void_p,
    wt.LPCWSTR,
    ctypes.c_void_p,
    wt.ULONG,
    wt.ULONG,
]
bcrypt.BCryptSetProperty.restype = wt.LONG
bcrypt.BCryptGetProperty.argtypes = [
    ctypes.c_void_p,
    wt.LPCWSTR,
    ctypes.c_void_p,
    wt.ULONG,
    ctypes.POINTER(wt.ULONG),
    wt.ULONG,
]
bcrypt.BCryptGetProperty.restype = wt.LONG
bcrypt.BCryptGenerateSymmetricKey.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_void_p,
    wt.ULONG,
    ctypes.c_void_p,
    wt.ULONG,
    wt.ULONG,
]
bcrypt.BCryptGenerateSymmetricKey.restype = wt.LONG
bcrypt.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
bcrypt.BCryptDestroyKey.restype = wt.LONG
bcrypt.BCryptDecrypt.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    wt.ULONG,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wt.ULONG,
    ctypes.c_void_p,
    wt.ULONG,
    ctypes.POINTER(wt.ULONG),
    wt.ULONG,
]
bcrypt.BCryptDecrypt.restype = wt.LONG


def _check_ntstatus(status: int, operation: str) -> None:
    if status != 0:
        unsigned = ctypes.c_ulong(status).value
        raise OSError(f"{operation} 失败，NTSTATUS 为 0x{unsigned:08X}")


class WindowsAesCbc:
    """Windows CNG（bcrypt.dll）的 AES-CBC 封装。"""

    def __init__(self) -> None:
        self._algorithm = ctypes.c_void_p()
        status = bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(self._algorithm), "AES", None, 0
        )
        _check_ntstatus(status, "BCryptOpenAlgorithmProvider")
        try:
            mode = "ChainingModeCBC\x00".encode("utf-16-le")
            mode_buffer = ctypes.create_string_buffer(mode)
            status = bcrypt.BCryptSetProperty(
                self._algorithm,
                "ChainingMode",
                mode_buffer,
                len(mode),
                0,
            )
            _check_ntstatus(status, "BCryptSetProperty(ChainingModeCBC)")
            self._key_object_length = self._get_ulong_property("ObjectLength")
            block_length = self._get_ulong_property("BlockLength")
            if block_length != 16:
                raise OSError(f"AES 块长度异常：{block_length}")
        except Exception:
            bcrypt.BCryptCloseAlgorithmProvider(self._algorithm, 0)
            self._algorithm = ctypes.c_void_p()
            raise

    def _get_ulong_property(self, name: str) -> int:
        value = wt.ULONG()
        written = wt.ULONG()
        status = bcrypt.BCryptGetProperty(
            self._algorithm,
            name,
            ctypes.byref(value),
            ctypes.sizeof(value),
            ctypes.byref(written),
            0,
        )
        _check_ntstatus(status, f"BCryptGetProperty({name})")
        return int(value.value)

    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        if len(key) != 16:
            raise ValueError("AES-128 密钥必须正好为 16 字节")
        if len(iv) != 16:
            raise ValueError("CBC IV 必须正好为 16 字节")
        if not ciphertext or len(ciphertext) % 16:
            raise ValueError("CBC 密文长度必须是 16 的非零倍数")

        key_handle = ctypes.c_void_p()
        key_object = ctypes.create_string_buffer(self._key_object_length)
        key_material = ctypes.create_string_buffer(key, len(key))
        status = bcrypt.BCryptGenerateSymmetricKey(
            self._algorithm,
            ctypes.byref(key_handle),
            key_object,
            self._key_object_length,
            key_material,
            len(key),
            0,
        )
        _check_ntstatus(status, "BCryptGenerateSymmetricKey")

        try:
            source = ctypes.create_string_buffer(ciphertext, len(ciphertext))
            iv_buffer = ctypes.create_string_buffer(iv, len(iv))
            output = ctypes.create_string_buffer(len(ciphertext))
            written = wt.ULONG()
            status = bcrypt.BCryptDecrypt(
                key_handle,
                source,
                len(ciphertext),
                None,
                iv_buffer,
                len(iv),
                output,
                len(ciphertext),
                ctypes.byref(written),
                0,
            )
            _check_ntstatus(status, "BCryptDecrypt")
            if written.value != len(ciphertext):
                raise OSError(
                    f"BCryptDecrypt 返回了 {written.value} 字节，"
                    f"预期为 {len(ciphertext)} 字节"
                )
            return output.raw[: written.value]
        finally:
            bcrypt.BCryptDestroyKey(key_handle)

    def close(self) -> None:
        if self._algorithm:
            bcrypt.BCryptCloseAlgorithmProvider(self._algorithm, 0)
            self._algorithm = ctypes.c_void_p()

    def __enter__(self) -> "WindowsAesCbc":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def cng_self_test(aes: WindowsAesCbc) -> None:
    """使用 NIST AES-CBC 测试向量校验 CNG 封装。"""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ciphertext = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    expected = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    actual = aes.decrypt(key, iv, ciphertext)
    if actual != expected:
        raise RuntimeError("Windows CNG AES-CBC 自检失败")


def _modmult(a: int, b: int, c: int, modulus: int, state: int) -> int:
    quotient = state // a
    state = b * (state - a * quotient) - c * quotient
    if state < 0:
        state += modulus
    return state


def generate_iv(page_number: int) -> bytes:
    state = page_number + 1
    initial = bytearray(16)
    for index in range(4):
        state = _modmult(52774, 40692, 3791, 2147483399, state)
        initial[index * 4 : index * 4 + 4] = struct.pack(
            "<I", state & 0xFFFFFFFF
        )
    return hashlib.md5(initial).digest()


def derive_page_key(raw_key: bytes, page_number: int) -> bytes:
    if len(raw_key) != 16:
        raise ValueError("企业微信原始数据库密钥必须为 16 字节")
    material = raw_key + struct.pack("<I", page_number) + WXSQLITE3_SALT
    return hashlib.md5(material).digest()


def is_plain_sqlite(page: bytes) -> bool:
    return page.startswith(SQLITE_HEADER)


def has_wxsqlite_header_fragment(page: bytes) -> bool:
    if len(page) < 24:
        return False
    header = page[16:24]
    page_size = (header[0] << 8) | header[1]
    if page_size == 1:
        page_size = 65536
    return (
        512 <= page_size <= 65536
        and page_size & (page_size - 1) == 0
        and header[5] == 0x40
        and header[6] == 0x20
        and header[7] == 0x20
    )


def is_wxsqlite_encrypted_page1(page: bytes) -> bool:
    if is_plain_sqlite(page) or not has_wxsqlite_header_fragment(page):
        return False
    encoded_page_size = (page[16] << 8) | page[17]
    if encoded_page_size == 1:
        encoded_page_size = 65536
    return encoded_page_size == PAGE_SIZE


def decrypt_page(
    aes: WindowsAesCbc, raw_key: bytes, page: bytes, page_number: int
) -> bytes:
    if len(page) != PAGE_SIZE:
        raise ValueError(f"数据库页应为 {PAGE_SIZE} 字节")
    page_key = derive_page_key(raw_key, page_number)
    iv = generate_iv(page_number)

    if page_number == 1 and has_wxsqlite_header_fragment(page):
        mutable = bytearray(page)
        expected_fragment = bytes(mutable[16:24])
        mutable[16:24] = mutable[8:16]
        mutable[16:] = aes.decrypt(page_key, iv, bytes(mutable[16:]))
        if bytes(mutable[16:24]) != expected_fragment:
            raise ValueError("候选密钥未通过 wxSQLite3 第 1 页校验")
        mutable[:16] = SQLITE_HEADER
        return bytes(mutable)

    return aes.decrypt(page_key, iv, page)


def looks_like_sqlite_page1(page: bytes) -> bool:
    if not page.startswith(SQLITE_HEADER) or len(page) < 108:
        return False
    page_size = struct.unpack(">H", page[16:18])[0]
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        return False
    return page[100] in (0x02, 0x05, 0x0A, 0x0D)


def verify_key(aes: WindowsAesCbc, candidate: bytes, page1: bytes) -> bool:
    if len(candidate) != 16 or len(page1) < PAGE_SIZE:
        return False
    try:
        decrypted = decrypt_page(aes, candidate, page1[:PAGE_SIZE], 1)
    except (OSError, ValueError):
        return False
    return looks_like_sqlite_page1(decrypted)


@dataclass(frozen=True)
class DatabaseFile:
    relative_path: Path
    absolute_path: Path
    page1: bytes
    encrypted: bool


def collect_databases(db_dir: Path) -> list[DatabaseFile]:
    databases: list[DatabaseFile] = []
    for path in sorted(db_dir.rglob("*.db")):
        if not path.is_file() or path.name.endswith(("-wal", "-shm")):
            continue
        if path.stat().st_size < PAGE_SIZE:
            continue
        with path.open("rb") as stream:
            page1 = stream.read(PAGE_SIZE)
        if is_plain_sqlite(page1):
            databases.append(
                DatabaseFile(path.relative_to(db_dir), path, page1, False)
            )
        elif is_wxsqlite_encrypted_page1(page1):
            databases.append(
                DatabaseFile(path.relative_to(db_dir), path, page1, True)
            )
    return databases


CORE_DATABASES = ("message.db", "session.db", "user.db")


def _looks_like_account_data_dir(path: Path) -> bool:
    return path.is_dir() and all((path / name).is_file() for name in CORE_DATABASES)


def _registry_data_locations() -> list[Path]:
    locations: list[Path] = []
    key_names = (
        r"Software\Tencent\WXWork",
        r"Software\WOW6432Node\Tencent\WXWork",
    )
    value_names = ("DataLocationPath", "DataSavePath")
    views = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)
    for key_name in key_names:
        for view in views:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    key_name,
                    0,
                    winreg.KEY_READ | view,
                )
            except OSError:
                continue
            with key:
                for value_name in value_names:
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                    except OSError:
                        continue
                    if isinstance(value, str) and value.strip():
                        locations.append(Path(os.path.expandvars(value.strip())))
    return locations


def discover_account_data_dirs(data_root: Optional[str] = None) -> list[Path]:
    roots: list[Path] = []
    if data_root:
        roots.append(Path(data_root))
    else:
        roots.extend(_registry_data_locations())
        appdata = os.environ.get("APPDATA")
        localappdata = os.environ.get("LOCALAPPDATA")
        if appdata:
            roots.append(Path(appdata) / "Tencent" / "WXWork")
        if localappdata:
            roots.append(Path(localappdata) / "Tencent" / "WXWork")

    found: dict[str, Path] = {}
    for original_root in roots:
        expanded = original_root.expanduser()
        candidates = (expanded, expanded / "WXWork")
        for root in candidates:
            if _looks_like_account_data_dir(root):
                found[str(root.resolve()).casefold()] = root.resolve()
            if not root.is_dir():
                continue
            try:
                children = list(root.iterdir())
            except OSError:
                continue
            for child in children:
                data_dir = child / "Data"
                if _looks_like_account_data_dir(data_dir):
                    found[str(data_dir.resolve()).casefold()] = data_dir.resolve()

    def latest_database_mtime(path: Path) -> float:
        return max((path / name).stat().st_mtime for name in CORE_DATABASES)

    return sorted(found.values(), key=latest_database_mtime, reverse=True)


def discover_sources(args: argparse.Namespace) -> int:
    sources = discover_account_data_dirs(args.data_root)
    result = {
        "success": True,
        "count": len(sources),
        "sources": [
            {
                "db_dir": str(path),
                "latest_core_db_mtime_utc": datetime.fromtimestamp(
                    max((path / name).stat().st_mtime for name in CORE_DATABASES),
                    timezone.utc,
                ).isoformat(),
                "core_databases": list(CORE_DATABASES),
            }
            for path in sources
        ],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def enumerate_wxwork_pids() -> list[int]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    current_session = wt.DWORD()
    if not kernel32.ProcessIdToSessionId(
        kernel32.GetCurrentProcessId(), ctypes.byref(current_session)
    ):
        kernel32.CloseHandle(snapshot)
        raise ctypes.WinError(ctypes.get_last_error())
    pids: list[int] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            raise ctypes.WinError(ctypes.get_last_error())
        while True:
            if entry.szExeFile.casefold() == "wxwork.exe":
                candidate_session = wt.DWORD()
                if kernel32.ProcessIdToSessionId(
                    entry.th32ProcessID, ctypes.byref(candidate_session)
                ) and candidate_session.value == current_session.value:
                    pids.append(int(entry.th32ProcessID))
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return pids


def iter_readable_regions(process: wt.HANDLE) -> Iterable[tuple[int, int]]:
    address = 0
    maximum_address = 0x7FFFFFFFFFFF
    mbi = MEMORY_BASIC_INFORMATION()
    while address < maximum_address:
        result = kernel32.VirtualQueryEx(
            process,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if not result:
            break
        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize)
        protection = int(mbi.Protect)
        base_protection = protection & 0xFF
        readable = (
            mbi.State == MEM_COMMIT
            and base_protection in READABLE_PAGE_TYPES
            and not protection & PAGE_GUARD
            and base_protection != PAGE_NOACCESS
            and 0 < size < 500 * 1024 * 1024
        )
        if readable:
            yield base, size
        next_address = base + size
        if next_address <= address:
            break
        address = next_address


def read_process_memory(
    process: wt.HANDLE, address: int, size: int
) -> Optional[bytes]:
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    success = kernel32.ReadProcessMemory(
        process,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )
    if not success or bytes_read.value == 0:
        return None
    return buffer.raw[: bytes_read.value]


HEX_KEY_PATTERN = re.compile(rb"x'([0-9a-fA-F]{32,192})'")


def candidate_keys_from_hex_blob(hex_blob: bytes) -> Iterable[bytes]:
    try:
        text = hex_blob.decode("ascii")
    except UnicodeDecodeError:
        return
    pieces: list[str] = []
    if len(text) >= 32:
        pieces.append(text[:32])
        pieces.append(text[-32:])
    if len(text) >= 64:
        pieces.append(text[32:64])
    seen: set[str] = set()
    for piece in pieces:
        if len(piece) != 32 or piece in seen:
            continue
        seen.add(piece)
        try:
            yield bytes.fromhex(piece)
        except ValueError:
            continue


def _candidate_has_entropy(candidate: bytes) -> bool:
    return (
        len(candidate) == 16
        and candidate != b"\x00" * 16
        and len(set(candidate)) >= 6
    )


def find_key_in_process(
    aes: WindowsAesCbc,
    pid: int,
    encrypted_pages: list[bytes],
    timeout: int,
    verbose: bool,
) -> Optional[bytes]:
    process = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not process:
        return None
    started = time.monotonic()
    seen_candidates: set[bytes] = set()
    try:
        regions = list(iter_readable_regions(process))
        if verbose:
            print(
                f"正在扫描 WXWork.exe PID {pid}：{len(regions)} 个可读内存区域",
                file=sys.stderr,
            )

        # Strategy 1: scan SQL-style x'0011...' key representations.
        for base, size in regions:
            if time.monotonic() - started > timeout:
                return None
            data = read_process_memory(process, base, size)
            if not data:
                continue
            for match in HEX_KEY_PATTERN.finditer(data):
                for candidate in candidate_keys_from_hex_blob(match.group(1)):
                    if candidate in seen_candidates or not _candidate_has_entropy(candidate):
                        continue
                    seen_candidates.add(candidate)
                    if any(verify_key(aes, candidate, page) for page in encrypted_pages):
                        return candidate

        # Strategy 2: locate likely wxSQLite cipher structures and validate the
        # 16 bytes at the known key slot.  Validation against page 1 is the
        # authority; structure flags only reduce the search space.
        for base, size in regions:
            if time.monotonic() - started > timeout:
                return None
            data = read_process_memory(process, base, size)
            if not data or len(data) < 64:
                continue
            limit = len(data) - 64
            for offset in range(0, limit, 4):
                if time.monotonic() - started > timeout:
                    return None
                flag0, flag4 = struct.unpack_from("<II", data, offset)
                if flag0 not in (1, 2) or flag4 not in (1, 2, 4096, 8192, 16384):
                    continue
                candidate = data[offset + 8 : offset + 24]
                if candidate in seen_candidates or not _candidate_has_entropy(candidate):
                    continue
                seen_candidates.add(candidate)
                if any(verify_key(aes, candidate, page) for page in encrypted_pages):
                    return candidate
    finally:
        kernel32.CloseHandle(process)
    return None


def recover_key(
    aes: WindowsAesCbc,
    databases: list[DatabaseFile],
    timeout: int,
    verbose: bool,
) -> bytes:
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError("当前 64 位企业微信版本需要 64 位 Python")
    if shell32.IsUserAnAdmin():
        raise RuntimeError(
            "拒绝使用已提升权限的令牌扫描进程内存；"
            "请以当前正常登录的 Windows 用户身份运行此命令"
        )
    encrypted_pages = [db.page1 for db in databases if db.encrypted]
    if not encrypted_pages:
        raise RuntimeError("未找到加密的 wxSQLite3 数据库")
    pids = enumerate_wxwork_pids()
    if not pids:
        raise RuntimeError("WXWork.exe 未运行")
    for pid in pids:
        candidate = find_key_in_process(
            aes, pid, encrypted_pages, timeout=timeout, verbose=verbose
        )
        if candidate is None:
            continue
        if all(verify_key(aes, candidate, page) for page in encrypted_pages):
            return candidate
        # Some database variants may not share the same layout.  The current
        # account is expected to use one global key, so require all recognized
        # encrypted DBs to validate before proceeding.
    raise RuntimeError("没有候选密钥能通过全部加密数据库的校验")


def doctor(args: argparse.Namespace) -> int:
    with WindowsAesCbc() as aes:
        cng_self_test(aes)
    sources = discover_account_data_dirs(args.data_root)
    pids = enumerate_wxwork_pids()
    result = {
        "success": True,
        "windows": platform.platform(),
        "python": platform.python_version(),
        "python_64_bit": ctypes.sizeof(ctypes.c_void_p) == 8,
        "sqlite": sqlite3.sqlite_version,
        "cng_aes_self_test": "ok",
        "elevated": bool(shell32.IsUserAnAdmin()),
        "same_session_wxwork_running": bool(pids),
        "same_session_wxwork_process_count": len(pids),
        "source_candidate_count": len(sources),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def decrypt_database_file(
    aes: WindowsAesCbc, source: Path, destination: Path, raw_key: bytes
) -> None:
    size = source.stat().st_size
    if size % PAGE_SIZE:
        raise ValueError(f"数据库大小未按页对齐：{source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".partial")
    try:
        with source.open("rb") as source_stream, partial.open("wb") as output_stream:
            page_number = 1
            while True:
                page = source_stream.read(PAGE_SIZE)
                if not page:
                    break
                if len(page) != PAGE_SIZE:
                    raise ValueError(f"数据库 {source} 中存在长度不足的数据页")
                output_stream.write(decrypt_page(aes, raw_key, page, page_number))
                page_number += 1
        os.replace(partial, destination)
    finally:
        if partial.exists():
            partial.unlink()


def _sqlite_readonly_uri(path: Path) -> str:
    return path.resolve().as_uri() + "?mode=ro&immutable=1"


def _assert_no_plaintext_wal(path: Path) -> None:
    wal_path = path.with_name(path.name + "-wal")
    try:
        wal_bytes = wal_path.stat().st_size
    except FileNotFoundError:
        return
    if wal_bytes:
        raise RuntimeError(
            f"存在非空明文 WAL，拒绝执行不可变查询："
            f"{wal_path}（{wal_bytes} 字节）。请查询已完成且保持静态的快照，"
            "并确保其 WAL 已完成 checkpoint 或物化。"
        )


def _open_sqlite_readonly(path: Path) -> sqlite3.Connection:
    _assert_no_plaintext_wal(path)
    connection = sqlite3.connect(_sqlite_readonly_uri(path), uri=True)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.row_factory = sqlite3.Row
    try:
        _assert_no_plaintext_wal(path)
    except Exception:
        connection.close()
        raise
    return connection


def sqlite_quick_check(path: Path) -> str:
    connection = _open_sqlite_readonly(path)
    try:
        rows = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
        return "ok" if rows == ["ok"] else "; ".join(rows) or "无结果"
    finally:
        connection.close()


def _has_reparse_component(path: Path) -> bool:
    current = path.absolute()
    while True:
        if current.exists():
            attributes = getattr(current.stat(), "st_file_attributes", 0)
            if current.is_symlink() or attributes & 0x400:
                return True
        if current.parent == current:
            return False
        current = current.parent


def assert_safe_output(db_dir: Path, out_dir: Path) -> None:
    source = db_dir.resolve()
    output = out_dir.resolve(strict=False)
    if source == output or source in output.parents or output in source.parents:
        raise ValueError(
            "输出目录必须与源目录树分离，且不能是源目录的祖先目录"
        )
    if out_dir.exists():
        raise FileExistsError(f"输出路径已存在；请选择一个全新目录：{out_dir}")
    if _has_reparse_component(out_dir.parent):
        raise ValueError("输出路径不得经过符号链接、目录联接或重解析点")


def collect_nonempty_wals(
    db_dir: Path, databases: list[DatabaseFile]
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for database in databases:
        wal = database.absolute_path.with_name(database.absolute_path.name + "-wal")
        if not wal.is_file() or wal.stat().st_size == 0:
            continue
        stat = wal.stat()
        result.append(
            {
                "relative_path": str(wal.relative_to(db_dir)),
                "bytes": stat.st_size,
                "modified_utc": datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc
                ).isoformat(),
            }
        )
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def decrypt_snapshot(args: argparse.Namespace) -> int:
    db_dir = Path(args.db_dir).resolve()
    out_dir = Path(args.out_dir).absolute()
    if not db_dir.is_dir():
        raise FileNotFoundError(f"数据库目录不存在：{db_dir}")
    assert_safe_output(db_dir, out_dir)

    databases = collect_databases(db_dir)
    if not databases:
        raise RuntimeError(f"在 {db_dir} 中未找到可识别的 SQLite 数据库")
    recognized_names = {database.relative_path.name.casefold() for database in databases}
    missing_core = [name for name in CORE_DATABASES if name.casefold() not in recognized_names]
    if missing_core:
        raise RuntimeError(f"缺少已识别的核心数据库：{', '.join(missing_core)}")

    nonempty_wals = collect_nonempty_wals(db_dir, databases)
    if nonempty_wals and not args.base_only:
        total_bytes = sum(int(item["bytes"]) for item in nonempty_wals)
        raise RuntimeError(
            f"发现 {len(nonempty_wals)} 个非空源 WAL 文件（{total_bytes} 字节）。"
            "这些记录完成物化前，不能将快照声明为完整。只有在用户明确接受不完整快照时，"
            "才使用 --base-only 重新运行。"
        )

    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = out_dir.parent / f".{out_dir.name}.staging-{uuid.uuid4().hex}"
    staging.mkdir()

    try:
        decrypted = 0
        copied = 0
        checks: dict[str, str] = {}
        hashes: dict[str, str] = {}
        with WindowsAesCbc() as aes:
            cng_self_test(aes)
            raw_key = recover_key(
                aes, databases, timeout=args.timeout, verbose=args.verbose
            )

            for database in databases:
                destination = staging / database.relative_path
                if database.encrypted:
                    decrypt_database_file(
                        aes, database.absolute_path, destination, raw_key
                    )
                    decrypted += 1
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(database.absolute_path, destination)
                    copied += 1
                check = sqlite_quick_check(destination)
                relative = str(database.relative_path)
                checks[relative] = check
                if check != "ok":
                    raise RuntimeError(
                        f"{database.relative_path} 的 SQLite 完整性检查失败：{check}"
                    )
                hashes[relative] = sha256_file(destination)

            # Best-effort release of the Python reference after decryption.
            raw_key = b""

        complete = not nonempty_wals
        manifest = {
            "format": "wecom-chat-vault-snapshot-v1",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "complete": complete,
            "base_only": bool(args.base_only),
            "third_party_dependencies": 0,
            "aes_provider": "Windows CNG bcrypt.dll",
            "wal_processed": False,
            "ignored_nonempty_wals": nonempty_wals,
            "databases": {
                relative: {"quick_check": checks[relative], "sha256": hashes[relative]}
                for relative in checks
            },
        }
        with (staging / "snapshot_manifest.json").open("w", encoding="utf-8") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2)
            stream.write("\n")

        os.replace(staging, out_dir)
    except Exception as error:
        if staging.exists():
            try:
                shutil.rmtree(staging)
            except Exception as cleanup_error:
                raise RuntimeError(
                    f"快照创建失败（{type(error).__name__}：{error}）；"
                    f"明文暂存目录的清理也失败，需要立即处理：{staging}"
                ) from cleanup_error
        raise

    result = {
        "success": True,
        "complete": complete,
        "base_only": bool(args.base_only),
        "third_party_dependencies": 0,
        "aes_provider": "Windows CNG bcrypt.dll",
        "recognized": len(databases),
        "decrypted": decrypted,
        "copied_plain": copied,
        "failed": 0,
        "output_dir": str(out_dir),
        "manifest": str(out_dir / "snapshot_manifest.json"),
        "quick_check": checks,
        "wal_processed": False,
        "ignored_nonempty_wals": nonempty_wals,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def inspect_snapshot(args: argparse.Namespace) -> int:
    directory = Path(args.decrypted_dir).resolve()
    if not directory.is_dir():
        raise FileNotFoundError(directory)
    result: dict[str, object] = {
        "directory": str(directory),
        "snapshot": _snapshot_status(directory),
        "databases": {},
    }
    database_results: dict[str, object] = {}
    for path in sorted(directory.rglob("*.db")):
        entry: dict[str, object] = {
            "bytes": path.stat().st_size,
            "quick_check": sqlite_quick_check(path),
        }
        if path.name == "message.db":
            connection = _open_sqlite_readonly(path)
            try:
                count, first, last = connection.execute(
                    "SELECT COUNT(*), MIN(send_time), MAX(send_time) FROM message_table"
                ).fetchone()
                entry["message_count"] = count
                entry["first_send_time_utc"] = _timestamp_to_utc_iso(first)
                entry["last_send_time_utc"] = _timestamp_to_utc_iso(last)
            finally:
                connection.close()
        database_results[str(path.relative_to(directory))] = entry
    result["databases"] = database_results
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _parse_message_content(raw: object) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw.strip()
    if not isinstance(raw, bytes):
        return str(raw).strip()
    decoded = raw.decode("utf-8", errors="ignore")
    chunks = re.findall(
        r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffefA-Za-z0-9]"
        r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffefA-Za-z0-9 "
        r".,;:!?，。！？、；：‘’“”（）【】《》\-_/\\@#\n\r\t]*",
        decoded,
    )
    cleaned = [" ".join(chunk.split()) for chunk in chunks]
    cleaned = [chunk for chunk in cleaned if len(chunk) >= 2]
    result = " ".join(cleaned).strip()
    result = re.sub(
        r"FileP2pPrefixKey\s*:\s*[0-9A-Fa-f\- ]{16,}",
        "FileP2pPrefixKey:[REDACTED]",
        result,
        flags=re.IGNORECASE,
    )
    result = re.sub(
        r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|"
        r"cookie|authorization|signature|filep2pprefixkey)\b(?:\s*[:=]\s*|\s+)"
        r"[^\s,;]{8,}",
        lambda match: f"{match.group(1)}:[REDACTED]",
        result,
    )
    result = re.sub(
        r"(?i)([?&](?:token|access_token|auth|key|signature|sig)(?:=|\s+))"
        r"[^&#\s]+",
        r"\1[REDACTED]",
        result,
    )
    result = re.sub(
        r"(?<![A-Za-z0-9])(?:[A-Za-z0-9+/_-]{64,}={0,2})(?![A-Za-z0-9])",
        "[LONG_TOKEN_REDACTED]",
        result,
    )
    return result or f"[binary {len(raw)} bytes]"


def _timestamp_to_utc_iso(value: object) -> Optional[str]:
    if value in (None, "", 0):
        return None
    numeric = float(value)
    while abs(numeric) > 32_503_680_000:
        numeric /= 1000
    return datetime.fromtimestamp(numeric, timezone.utc).isoformat()


def _load_user_names(directory: Path) -> dict[str, str]:
    path = directory / "user.db"
    if not path.is_file():
        return {}
    connection = _open_sqlite_readonly(path)
    try:
        return {
            str(row["id"]): (
                row["name"] or row["english_name"] or str(row["id"])
            )
            for row in connection.execute(
                "SELECT id, name, english_name FROM user_table"
            )
        }
    finally:
        connection.close()


def _snapshot_status(directory: Path) -> dict[str, object]:
    manifest_path = directory / "snapshot_manifest.json"
    if not manifest_path.is_file():
        return {
            "manifest_present": False,
            "complete": None,
            "warning": "未找到快照清单；无法判断时效性和 WAL 完整性",
        }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {
            "manifest_present": True,
            "complete": None,
            "warning": f"无法读取快照清单：{type(error).__name__}",
        }
    ignored_wals = manifest.get("ignored_nonempty_wals") or []
    result: dict[str, object] = {
        "manifest_present": True,
        "complete": manifest.get("complete"),
        "created_utc": manifest.get("created_utc"),
        "wal_processed": manifest.get("wal_processed"),
        "base_only": manifest.get("base_only"),
    }
    if ignored_wals:
        result["ignored_nonempty_wals"] = ignored_wals
    if manifest.get("complete") is not True:
        result["warning"] = (
            "快照不完整：源 WAL 记录尚未物化，近期消息可能缺失"
        )
    elif ignored_wals:
        result["warning"] = (
            "快照清单状态不一致：既标记为完整，又列出了被忽略的非空 WAL 文件"
        )
    return result


def list_sessions(args: argparse.Namespace) -> int:
    directory = Path(args.decrypted_dir).resolve()
    path = directory / "session.db"
    if not path.is_file():
        raise FileNotFoundError(path)
    connection = _open_sqlite_readonly(path)
    try:
        query = (
            "SELECT id, name, roomname_remark, last_message_time, "
            "last_message_id, is_sticked FROM conversation_table"
        )
        parameters: list[object] = []
        if args.keyword:
            query += " WHERE name LIKE ? OR roomname_remark LIKE ?"
            value = f"%{args.keyword}%"
            parameters.extend([value, value])
        query += " ORDER BY last_message_time DESC LIMIT ?"
        parameters.append(args.limit)
        rows = []
        for row in connection.execute(query, parameters):
            item = dict(row)
            timestamp = item.get("last_message_time")
            item["last_message_time_utc"] = _timestamp_to_utc_iso(timestamp)
            rows.append(item)
    finally:
        connection.close()
    print(
        json.dumps(
            {
                "snapshot": _snapshot_status(directory),
                "count": len(rows),
                "sessions": rows,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _message_to_dict(row: sqlite3.Row, user_names: dict[str, str]) -> dict[str, object]:
    timestamp = row["send_time"]
    sender_id = row["sender_id"]
    return {
        "message_id": row["message_id"],
        "sequence": row["sequence"],
        "conversation_id": row["conversation_id"],
        "sender_id": sender_id,
        "sender_name": user_names.get(str(sender_id), str(sender_id)),
        "content_type": row["content_type"],
        "send_time": timestamp,
        "send_time_utc": _timestamp_to_utc_iso(timestamp),
        "content": _parse_message_content(row["content"]),
    }


def list_messages(args: argparse.Namespace) -> int:
    directory = Path(args.decrypted_dir).resolve()
    path = directory / "message.db"
    if not path.is_file():
        raise FileNotFoundError(path)
    user_names = _load_user_names(directory)
    connection = _open_sqlite_readonly(path)
    try:
        query = (
            "SELECT message_id, sequence, conversation_id, sender_id, "
            "content_type, send_time, content FROM message_table "
            "WHERE conversation_id = ?"
        )
        parameters: list[object] = [args.conversation_id]
        if args.since is not None:
            query += " AND send_time >= ?"
            parameters.append(args.since)
        if args.until is not None:
            query += " AND send_time < ?"
            parameters.append(args.until)
        query += " ORDER BY sequence DESC LIMIT ?"
        parameters.append(args.limit)
        messages = [
            _message_to_dict(row, user_names)
            for row in connection.execute(query, parameters)
        ]
        messages.reverse()
    finally:
        connection.close()
    print(
        json.dumps(
            {
                "snapshot": _snapshot_status(directory),
                "count": len(messages),
                "messages": messages,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def search_messages(args: argparse.Namespace) -> int:
    directory = Path(args.decrypted_dir).resolve()
    path = directory / "message.db"
    if not path.is_file():
        raise FileNotFoundError(path)
    user_names = _load_user_names(directory)
    connection = _open_sqlite_readonly(path)
    try:
        query = (
            "SELECT message_id, sequence, conversation_id, sender_id, "
            "content_type, send_time, content FROM message_table"
        )
        parameters: list[object] = []
        clauses: list[str] = []
        if args.conversation_id:
            clauses.append("conversation_id = ?")
            parameters.append(args.conversation_id)
        if args.since is not None:
            clauses.append("send_time >= ?")
            parameters.append(args.since)
        if args.until is not None:
            clauses.append("send_time < ?")
            parameters.append(args.until)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY sequence DESC"
        keyword = args.keyword.casefold()
        messages = []
        for row in connection.execute(query, parameters):
            item = _message_to_dict(row, user_names)
            if keyword not in str(item["content"]).casefold():
                continue
            messages.append(item)
            if len(messages) >= args.limit:
                break
        messages.reverse()
    finally:
        connection.close()
    print(
        json.dumps(
            {
                "snapshot": _snapshot_status(directory),
                "count": len(messages),
                "messages": messages,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def bounded_positive_int(value: str, maximum: int = 10_000) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("必须是整数") from error
    if parsed < 1 or parsed > maximum:
        raise argparse.ArgumentTypeError(f"必须介于 1 和 {maximum} 之间")
    return parsed


def nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("必须是整数") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("必须大于或等于 0")
    return parsed


def timeout_seconds(value: str) -> int:
    return bounded_positive_int(value, maximum=3600)


class ChineseArgumentParser(argparse.ArgumentParser):
    """将 argparse 的固定帮助标签本地化为中文。"""

    def __init__(self, *args, **kwargs) -> None:
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)
        self._positionals.title = "位置参数"
        self._optionals.title = "选项"
        self.add_argument(
            "-h", "--help", action="help", help="显示此帮助信息并退出"
        )

    def format_usage(self) -> str:
        return super().format_usage().replace("usage: ", "用法：", 1)

    def format_help(self) -> str:
        return super().format_help().replace("usage: ", "用法：", 1)


def build_parser() -> argparse.ArgumentParser:
    parser = ChineseArgumentParser(
        description=(
            "WeComCracker：仅使用 Python 标准库和 Windows CNG 解密并查询企业微信本地 "
            "wxSQLite3 快照。"
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser(
        "discover", help="定位当前用户的企业微信账号数据库目录"
    )
    discover_parser.add_argument(
        "--data-root",
        help="可选：检查指定的企业微信数据根目录，而不使用注册表默认位置",
    )
    discover_parser.set_defaults(handler=discover_sources)

    doctor_parser = subparsers.add_parser(
        "doctor", help="检查 Windows、CNG、Python、SQLite、企业微信及数据发现状态"
    )
    doctor_parser.add_argument("--data-root", help="可选的企业微信数据根目录")
    doctor_parser.set_defaults(handler=doctor)

    decrypt_parser = subparsers.add_parser("decrypt", help="创建明文数据库快照")
    decrypt_parser.add_argument("--db-dir", required=True, help="企业微信账号的 Data 数据库目录")
    decrypt_parser.add_argument("--out-dir", required=True, help="必须尚不存在的明文快照输出目录")
    decrypt_parser.add_argument("--timeout", type=timeout_seconds, default=120, help="扫描每个进程的超时秒数（默认：120）")
    decrypt_parser.add_argument("--verbose", action="store_true", help="输出扫描进度")
    decrypt_parser.add_argument(
        "--base-only",
        action="store_true",
        help=(
            "明确接受忽略非空源 WAL 文件的不完整快照"
        ),
    )
    decrypt_parser.set_defaults(handler=decrypt_snapshot)

    inspect_parser = subparsers.add_parser(
        "inspect", help="在不修改快照的前提下检查已解密快照"
    )
    inspect_parser.add_argument("--decrypted-dir", required=True, help="明文快照目录")
    inspect_parser.set_defaults(handler=inspect_snapshot)

    sessions_parser = subparsers.add_parser(
        "sessions", help="列出明文快照中的会话"
    )
    sessions_parser.add_argument("--decrypted-dir", required=True, help="明文快照目录")
    sessions_parser.add_argument("--keyword", help="按会话名称或备注筛选的关键词")
    sessions_parser.add_argument(
        "--limit",
        type=bounded_positive_int,
        default=50,
        help="最多返回的会话数（1-10000；默认：50）",
    )
    sessions_parser.set_defaults(handler=list_sessions)

    messages_parser = subparsers.add_parser(
        "messages", help="读取单个会话中的消息"
    )
    messages_parser.add_argument("--decrypted-dir", required=True, help="明文快照目录")
    messages_parser.add_argument("--conversation-id", required=True, help="会话 ID")
    messages_parser.add_argument(
        "--limit",
        type=bounded_positive_int,
        default=50,
        help="最多返回的消息数（1-10000；默认：50）",
    )
    messages_parser.add_argument("--since", type=nonnegative_int, help="起始 Unix 秒时间戳（包含）")
    messages_parser.add_argument("--until", type=nonnegative_int, help="结束 Unix 秒时间戳（包含）")
    messages_parser.set_defaults(handler=list_messages)

    search_parser = subparsers.add_parser(
        "search", help="搜索明文快照中解析出的消息文本"
    )
    search_parser.add_argument("--decrypted-dir", required=True, help="明文快照目录")
    search_parser.add_argument("--keyword", required=True, help="要搜索的关键词")
    search_parser.add_argument("--conversation-id", help="可选：只搜索指定会话 ID")
    search_parser.add_argument("--since", type=nonnegative_int, help="起始 Unix 秒时间戳（包含）")
    search_parser.add_argument("--until", type=nonnegative_int, help="结束 Unix 秒时间戳（包含）")
    search_parser.add_argument(
        "--limit",
        type=bounded_positive_int,
        default=50,
        help=(
            "最多返回的解析匹配数（1-10000；默认：50）；按从新到旧扫描符合条件的消息，"
            "直到找到指定数量的匹配"
        ),
    )
    search_parser.set_defaults(handler=search_messages)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.handler(args))
    except Exception as error:
        print(
            json.dumps(
                {"success": False, "error": f"{type(error).__name__}: {error}"},
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
