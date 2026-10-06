"""PE (Windows) binary generation.

Generates minimal PE64 (x86_64) Windows executables that import
Windows API functions from multiple DLLs via an Import Address Table
(IAT) at known virtual addresses.

Waypoint 1 — Dynamic IAT:
  The builder accepts an optional list of required API names (or a full
  OrderedDict of DLL → functions).  When omitted it falls back to the
  classic full set so all existing tests and helpers keep working.
  A symbol→DLL catalogue is maintained so any known API can be requested
  without editing the PE builder.
"""

from __future__ import annotations

import struct
from collections import OrderedDict
from typing import Iterable, Mapping, Sequence

# ---------------------------------------------------------------------------
# PE constants
# ---------------------------------------------------------------------------
PE_IMAGE_BASE = 0x400000
PE_SECTION_ALIGNMENT = 0x1000
PE_FILE_ALIGNMENT = 0x200
PE_CODE_RVA = 0x1000
PE_IDATA_RVA = 0x2000

IMAGE_FILE_MACHINE_AMD64 = 0x8664

# ---------------------------------------------------------------------------
# Known symbol → DLL catalogue (easily extended)
# ---------------------------------------------------------------------------
# This is the authoritative mapping used when the caller only supplies a
# list of function names.  Add new APIs here; the dynamic builder will
# pick them up automatically.
_SYMBOL_TO_DLL: dict[str, str] = {
    # kernel32
    "ExitProcess": "kernel32.dll",
    "GetStdHandle": "kernel32.dll",
    "WriteFile": "kernel32.dll",
    "ReadFile": "kernel32.dll",
    "CreateFileA": "kernel32.dll",
    "CloseHandle": "kernel32.dll",
    "GetFileSize": "kernel32.dll",
    "GetComputerNameA": "kernel32.dll",
    "GetLocalTime": "kernel32.dll",
    "GlobalMemoryStatusEx": "kernel32.dll",
    "GetCurrentProcessId": "kernel32.dll",
    "GetCommandLineA": "kernel32.dll",
    "Sleep": "kernel32.dll",
    "GetProcessHeap": "kernel32.dll",
    "HeapAlloc": "kernel32.dll",
    "HeapFree": "kernel32.dll",
    "FindFirstFileA": "kernel32.dll",
    "FindNextFileA": "kernel32.dll",
    "FindClose": "kernel32.dll",
    "SetConsoleTitleA": "kernel32.dll",
    "GetLastError": "kernel32.dll",
    "lstrlenA": "kernel32.dll",
    "GetEnvironmentVariableA": "kernel32.dll",
    "GetTickCount64": "kernel32.dll",
    "GetCurrentDirectoryA": "kernel32.dll",
    "GetTempPathA": "kernel32.dll",
    "DeleteFileA": "kernel32.dll",
    "CopyFileA": "kernel32.dll",
    "CreateDirectoryA": "kernel32.dll",
    # Extra common kernel32 APIs (not in the original 35)
    "GetModuleHandleA": "kernel32.dll",
    "GetProcAddress": "kernel32.dll",
    "LoadLibraryA": "kernel32.dll",
    "FreeLibrary": "kernel32.dll",
    "VirtualAlloc": "kernel32.dll",
    "VirtualFree": "kernel32.dll",
    "CreateThread": "kernel32.dll",
    "WaitForSingleObject": "kernel32.dll",
    "GetSystemTimeAsFileTime": "kernel32.dll",
    "QueryPerformanceCounter": "kernel32.dll",
    "QueryPerformanceFrequency": "kernel32.dll",
    "SetConsoleMode": "kernel32.dll",
    "GetConsoleMode": "kernel32.dll",
    "FlushFileBuffers": "kernel32.dll",
    "SetFilePointer": "kernel32.dll",
    "GetFileAttributesA": "kernel32.dll",
    "CreateProcessA": "kernel32.dll",
    "TerminateProcess": "kernel32.dll",
    "GetCurrentProcess": "kernel32.dll",
    "GetCurrentThreadId": "kernel32.dll",
    "TlsAlloc": "kernel32.dll",
    "TlsGetValue": "kernel32.dll",
    "TlsSetValue": "kernel32.dll",
    "TlsFree": "kernel32.dll",
    # user32
    "MessageBoxA": "user32.dll",
    "MessageBoxW": "user32.dll",
    "GetForegroundWindow": "user32.dll",
    "FindWindowA": "user32.dll",
    "ShowWindow": "user32.dll",
    "UpdateWindow": "user32.dll",
    "GetMessageA": "user32.dll",
    "TranslateMessage": "user32.dll",
    "DispatchMessageA": "user32.dll",
    "PostQuitMessage": "user32.dll",
    "DefWindowProcA": "user32.dll",
    "RegisterClassExA": "user32.dll",
    "CreateWindowExA": "user32.dll",
    "DestroyWindow": "user32.dll",
    "SetWindowTextA": "user32.dll",
    "GetWindowTextA": "user32.dll",
    # wininet (kept for backward compatibility with existing helpers)
    "InternetOpenA": "wininet.dll",
    "InternetOpenUrlA": "wininet.dll",
    "InternetReadFile": "wininet.dll",
    "InternetCloseHandle": "wininet.dll",
    # winhttp (commonly preferred over wininet)
    "WinHttpOpen": "winhttp.dll",
    "WinHttpConnect": "winhttp.dll",
    "WinHttpOpenRequest": "winhttp.dll",
    "WinHttpSendRequest": "winhttp.dll",
    "WinHttpReceiveResponse": "winhttp.dll",
    "WinHttpReadData": "winhttp.dll",
    "WinHttpCloseHandle": "winhttp.dll",
    "WinHttpQueryDataAvailable": "winhttp.dll",
    # shell32
    "ShellExecuteA": "shell32.dll",
    "ShellExecuteW": "shell32.dll",
    "SHGetFolderPathA": "shell32.dll",
    # advapi32
    "RegOpenKeyExA": "advapi32.dll",
    "RegQueryValueExA": "advapi32.dll",
    "RegCloseKey": "advapi32.dll",
    "RegSetValueExA": "advapi32.dll",
    "GetUserNameA": "advapi32.dll",
    # ws2_32 (basic sockets)
    "WSAStartup": "ws2_32.dll",
    "WSACleanup": "ws2_32.dll",
    "socket": "ws2_32.dll",
    "connect": "ws2_32.dll",
    "send": "ws2_32.dll",
    "recv": "ws2_32.dll",
    "closesocket": "ws2_32.dll",
    "htons": "ws2_32.dll",
    "inet_addr": "ws2_32.dll",
}

# Canonical full import set used by the original BinaryVibes (order matters
# for stable addresses of the classic 35 APIs).
_DEFAULT_PE_IMPORTS: OrderedDict[str, list[str]] = OrderedDict([
    ("kernel32.dll", [
        "ExitProcess",
        "GetStdHandle",
        "WriteFile",
        "ReadFile",
        "CreateFileA",
        "CloseHandle",
        "GetFileSize",
        "GetComputerNameA",
        "GetLocalTime",
        "GlobalMemoryStatusEx",
        "GetCurrentProcessId",
        "GetCommandLineA",
        "Sleep",
        "GetProcessHeap",
        "HeapAlloc",
        "HeapFree",
        "FindFirstFileA",
        "FindNextFileA",
        "FindClose",
        "SetConsoleTitleA",
        "GetLastError",
        "lstrlenA",
        "GetEnvironmentVariableA",
        "GetTickCount64",
        "GetCurrentDirectoryA",
        "GetTempPathA",
        "DeleteFileA",
        "CopyFileA",
        "CreateDirectoryA",
    ]),
    ("user32.dll", [
        "MessageBoxA",
    ]),
    ("wininet.dll", [
        "InternetOpenA",
        "InternetOpenUrlA",
        "InternetReadFile",
        "InternetCloseHandle",
    ]),
    ("shell32.dll", [
        "ShellExecuteA",
    ]),
])

# Backward-compatible alias used by tests and external code.
_PE_IMPORTS = _DEFAULT_PE_IMPORTS


def compute_iat_exports(
    imports: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, int]:
    """Compute the virtual-address map for a given import set.

    Addresses are assigned contiguously starting at
    ``PE_IMAGE_BASE + PE_IDATA_RVA``.  Each DLL group is followed by an
    8-byte null terminator.
    """
    if imports is None:
        imports = _DEFAULT_PE_IMPORTS

    exports: dict[str, int] = {}
    offset = 0
    for _dll_name, functions in imports.items():
        for func in functions:
            exports[func] = PE_IMAGE_BASE + PE_IDATA_RVA + offset
            offset += 8
        offset += 8  # null terminator between DLLs
    return exports


# Module-level map for the default (full) set — keeps all existing
# helpers and prompts working with the classic addresses.
PE_IAT_EXPORTS: dict[str, int] = compute_iat_exports(_DEFAULT_PE_IMPORTS)


def resolve_imports(
    symbols: Iterable[str] | None = None,
) -> OrderedDict[str, list[str]]:
    """Build a minimal OrderedDict[DLL, functions] from a list of symbols.

    Unknown symbols raise ``ValueError``.  When *symbols* is None the
    full default set is returned.
    """
    if symbols is None:
        return OrderedDict(
            (dll, list(funcs)) for dll, funcs in _DEFAULT_PE_IMPORTS.items()
        )

    # Preserve a stable order: first by the order of first appearance of
    # each DLL in the default set / catalogue, then by the order the
    # symbols were requested.
    dll_order: list[str] = []
    dll_funcs: dict[str, list[str]] = {}

    for sym in symbols:
        dll = _SYMBOL_TO_DLL.get(sym)
        if dll is None:
            raise ValueError(
                f"Unknown API symbol '{sym}'.  "
                f"Add it to _SYMBOL_TO_DLL in pe.py."
            )
        if dll not in dll_funcs:
            dll_order.append(dll)
            dll_funcs[dll] = []
        if sym not in dll_funcs[dll]:
            dll_funcs[dll].append(sym)

    return OrderedDict((dll, dll_funcs[dll]) for dll in dll_order)


def extract_pe_symbols(assembly: str) -> list[str]:
    """Extract Windows API symbols referenced in assembly text.

    Detects:
      1. Absolute IAT addresses that match the classic ``PE_IAT_EXPORTS``
         map (e.g. ``mov eax, 0x402000`` → ExitProcess).
      2. Bare API names that appear in the symbol catalogue (future-proof
         for prompts that emit names instead of addresses).

    Always includes ``ExitProcess`` so every PE can terminate cleanly.
    Order is stable: ExitProcess first, then discovery order.
    """
    import re

    found: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        if name not in seen and name in _SYMBOL_TO_DLL:
            seen.add(name)
            found.append(name)

    # 1. Reverse-lookup classic IAT addresses that appear in the text.
    #    Match both 0x402000 and 402000h style immediates.
    addr_to_sym = {addr: name for name, addr in PE_IAT_EXPORTS.items()}
    for match in re.finditer(r"0x([0-9a-fA-F]{5,8})\b", assembly):
        addr = int(match.group(1), 16)
        if addr in addr_to_sym:
            _add(addr_to_sym[addr])

    # 2. Bare symbol names (word boundaries, avoid matching inside labels).
    for name in _SYMBOL_TO_DLL:
        # Require the name to appear as a standalone token
        if re.search(rf"\b{re.escape(name)}\b", assembly):
            _add(name)

    # Every PE needs a way to exit.
    _add("ExitProcess")

    return found


def rewrite_iat_addresses(
    assembly: str,
    new_exports: Mapping[str, int],
    old_exports: Mapping[str, int] | None = None,
) -> str:
    """Rewrite absolute IAT addresses in *assembly* to match *new_exports*.

    Used when building a minimal dynamic IAT so that both LLM-generated
    code and the pre-baked runtime helpers (which were written against the
    classic full IAT layout) point at the correct slots.
    """
    import re

    if old_exports is None:
        old_exports = PE_IAT_EXPORTS

    # Build old-addr → new-addr map for symbols present in both.
    replacements: dict[int, int] = {}
    for name, new_addr in new_exports.items():
        old_addr = old_exports.get(name)
        if old_addr is not None and old_addr != new_addr:
            replacements[old_addr] = new_addr

    if not replacements:
        return assembly

    def _repl(match: re.Match[str]) -> str:
        addr = int(match.group(1), 16)
        if addr in replacements:
            return f"0x{replacements[addr]:X}"
        return match.group(0)

    return re.sub(r"0x([0-9a-fA-F]{5,8})\b", _repl, assembly)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _align(value: int, alignment: int) -> int:
    """Round *value* up to the next multiple of *alignment*."""
    return (value + alignment - 1) & ~(alignment - 1)


def _build_idata_section(
    imports: Mapping[str, Sequence[str]] | None = None,
) -> tuple[bytes, int, int, int]:
    """Build the .idata section with import tables for the given DLLs.

    When *imports* is omitted the classic full set is used (backward
    compatible with existing tests).

    Internal layout (offsets relative to section start, i.e. RVA 0x2000)::

        [All IATs]          contiguous: dll1 IAT + null | dll2 IAT + null | …
        [All ILTs]          contiguous: dll1 ILT + null | dll2 ILT + null | …
        [IDT]               (num_dlls + 1) * 20   Import Directory Table
        [Hint/Name entries] variable               2-byte hint + ASCII name
        [DLL name strings]  variable

    Returns:
        ``(section_bytes, iat_offset, ilt_offset, idt_offset)``
    """
    if imports is None:
        imports = _DEFAULT_PE_IMPORTS

    # Total IAT/ILT entry count (functions + one null terminator per DLL)
    total_iat_entries = sum(len(funcs) + 1 for funcs in imports.values())
    total_table_size = total_iat_entries * 8

    iat_offset = 0
    ilt_offset = total_table_size
    num_dlls = len(imports)
    idt_offset = ilt_offset + total_table_size
    idt_size = (num_dlls + 1) * 20
    hint_names_start = idt_offset + idt_size

    # -- Hint/Name entries for ALL functions --------------------------------
    hint_names = bytearray()
    dll_hint_rvas: dict[str, list[int]] = {}
    for dll_name, functions in imports.items():
        rvas: list[int] = []
        for func in functions:
            rva = PE_IDATA_RVA + hint_names_start + len(hint_names)
            rvas.append(rva)
            entry = struct.pack("<H", 0) + func.encode("ascii") + b"\x00"
            if len(entry) % 2:
                entry += b"\x00"  # pad to even boundary
            hint_names += entry
        dll_hint_rvas[dll_name] = rvas

    # -- DLL name strings ---------------------------------------------------
    dll_name_rvas: dict[str, int] = {}
    dll_names_data = bytearray()
    for dll_name in imports:
        rva = PE_IDATA_RVA + hint_names_start + len(hint_names) + len(dll_names_data)
        dll_name_rvas[dll_name] = rva
        dll_names_data += dll_name.encode("ascii") + b"\x00"

    # -- IAT & ILT (identical at link time; loader patches IAT) -------------
    iat = bytearray()
    ilt = bytearray()
    dll_iat_offsets: dict[str, int] = {}
    dll_ilt_offsets: dict[str, int] = {}

    current_offset = 0
    for dll_name, _functions in imports.items():
        dll_iat_offsets[dll_name] = current_offset
        dll_ilt_offsets[dll_name] = total_table_size + current_offset

        for rva in dll_hint_rvas[dll_name]:
            entry = struct.pack("<Q", rva)
            iat += entry
            ilt += entry
            current_offset += 8
        # Null terminator for this DLL
        iat += struct.pack("<Q", 0)
        ilt += struct.pack("<Q", 0)
        current_offset += 8

    # -- Import Directory Table (IDT) ---------------------------------------
    idt = bytearray()
    for dll_name in imports:
        idt += struct.pack(
            "<IIIII",
            PE_IDATA_RVA + dll_ilt_offsets[dll_name],  # OriginalFirstThunk
            0,                                           # TimeDateStamp
            0,                                           # ForwarderChain
            dll_name_rvas[dll_name],                     # Name
            PE_IDATA_RVA + dll_iat_offsets[dll_name],   # FirstThunk
        )
    idt += b"\x00" * 20  # null terminator entry

    section = bytes(iat) + bytes(ilt) + bytes(idt) + bytes(hint_names) + bytes(dll_names_data)
    return section, iat_offset, ilt_offset, idt_offset


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_pe64(
    code: bytes,
    data: bytes = b"",
    *,
    imports: Mapping[str, Sequence[str]] | None = None,
    symbols: Iterable[str] | None = None,
) -> bytes:
    """Generate a minimal PE64 (x86_64) Windows executable.

    By default the classic full import set is used so that all existing
    helpers and hardcoded IAT addresses remain valid.

    To build a *minimal* IAT supply either:

    - ``imports``: an OrderedDict / dict of ``{dll_name: [func, …]}``, or
    - ``symbols``: an iterable of API names; the builder looks them up in
      the symbol catalogue and groups them by DLL automatically.

    Args:
        code: Machine code placed at the start of the ``.text`` section.
        data: Optional data appended after *code* in the same section.
        imports: Explicit DLL → function list (takes precedence).
        symbols: Convenience list of function names to import.

    Returns:
        Complete PE file as :class:`bytes`.
    """
    if imports is not None and symbols is not None:
        raise ValueError("Pass either 'imports' or 'symbols', not both")

    if imports is None:
        if symbols is not None:
            imports = resolve_imports(symbols)
        else:
            imports = _DEFAULT_PE_IMPORTS

    payload = code + data

    # -- .idata section -----------------------------------------------------
    idata_raw, iat_off, _ilt_off, idt_off = _build_idata_section(imports)

    total_iat_entries = sum(len(funcs) + 1 for funcs in imports.values())
    iat_size = total_iat_entries * 8
    num_dlls = len(imports)
    idt_size = (num_dlls + 1) * 20

    # -- sizes (file layout) ------------------------------------------------
    headers_size = PE_FILE_ALIGNMENT  # 0x200
    text_raw_size = _align(max(len(payload), 1), PE_FILE_ALIGNMENT)
    idata_raw_size = _align(len(idata_raw), PE_FILE_ALIGNMENT)

    text_file_offset = headers_size
    idata_file_offset = text_file_offset + text_raw_size

    # Virtual image size (headers + .text + .idata pages)
    size_of_image = _align(
        PE_IDATA_RVA + len(idata_raw), PE_SECTION_ALIGNMENT,
    )

    # ── DOS Header (64 bytes) ─────────────────────────────────────────────
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)  # e_lfanew → offset of PE sig

    # ── PE Signature (4 bytes) ────────────────────────────────────────────
    pe_sig = b"PE\x00\x00"

    # ── COFF File Header (20 bytes) ───────────────────────────────────────
    coff = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_AMD64,  # Machine
        2,                          # NumberOfSections
        0,                          # TimeDateStamp
        0,                          # PointerToSymbolTable
        0,                          # NumberOfSymbols
        240,                        # SizeOfOptionalHeader (PE32+)
        0x22,                       # Characteristics (EXECUTABLE | LARGE_ADDRESS_AWARE)
    )

    # ── Optional Header — standard fields (24 bytes) ──────────────────────
    opt_std = struct.pack(
        "<HBBIIIII",
        0x20B,          # Magic (PE32+)
        14,             # MajorLinkerVersion
        0,              # MinorLinkerVersion
        text_raw_size,  # SizeOfCode
        idata_raw_size, # SizeOfInitializedData
        0,              # SizeOfUninitializedData
        PE_CODE_RVA,    # AddressOfEntryPoint
        PE_CODE_RVA,    # BaseOfCode
    )

    # ── Optional Header — Windows-specific fields (88 bytes) ──────────────
    opt_win = struct.pack(
        "<QIIHHHHHHIIIIHHQQQQII",
        PE_IMAGE_BASE,          # ImageBase
        PE_SECTION_ALIGNMENT,   # SectionAlignment
        PE_FILE_ALIGNMENT,      # FileAlignment
        6,                      # MajorOperatingSystemVersion
        0,                      # MinorOperatingSystemVersion
        0,                      # MajorImageVersion
        0,                      # MinorImageVersion
        6,                      # MajorSubsystemVersion
        0,                      # MinorSubsystemVersion
        0,                      # Win32VersionValue
        size_of_image,          # SizeOfImage
        headers_size,           # SizeOfHeaders
        0,                      # CheckSum
        3,                      # Subsystem (IMAGE_SUBSYSTEM_WINDOWS_CUI)
        0x8100,                 # DllCharacteristics (ASLR disabled)
        0x100000,               # SizeOfStackReserve
        0x1000,                 # SizeOfStackCommit
        0x100000,               # SizeOfHeapReserve
        0x1000,                 # SizeOfHeapCommit
        0,                      # LoaderFlags
        16,                     # NumberOfRvaAndSizes
    )

    # ── Data directories (16 x 8 = 128 bytes) ────────────────────────────
    data_dirs = bytearray(128)
    # [1] Import Table → IDT
    struct.pack_into("<II", data_dirs, 1 * 8,
                     PE_IDATA_RVA + idt_off, idt_size)
    # [12] IAT
    struct.pack_into("<II", data_dirs, 12 * 8,
                     PE_IDATA_RVA + iat_off, iat_size)

    optional = opt_std + opt_win + bytes(data_dirs)

    # ── Section headers (40 bytes each) ───────────────────────────────────
    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(payload),       # VirtualSize
        PE_CODE_RVA,        # VirtualAddress
        text_raw_size,      # SizeOfRawData
        text_file_offset,   # PointerToRawData
        0, 0, 0, 0,
        0x60000020,         # CODE | EXECUTE | READ
    )

    sec_idata = struct.pack(
        "<8sIIIIIIHHI",
        b".idata\x00\x00",
        len(idata_raw),     # VirtualSize
        PE_IDATA_RVA,       # VirtualAddress
        idata_raw_size,     # SizeOfRawData
        idata_file_offset,  # PointerToRawData
        0, 0, 0, 0,
        0xC0000040,         # INITIALIZED_DATA | READ | WRITE
    )

    # ── Assemble ──────────────────────────────────────────────────────────
    hdr = bytes(dos) + pe_sig + coff + optional + sec_text + sec_idata
    hdr_padded = hdr + b"\x00" * (headers_size - len(hdr))

    text_padded = payload + b"\x00" * (text_raw_size - len(payload))
    idata_padded = idata_raw + b"\x00" * (idata_raw_size - len(idata_raw))

    return hdr_padded + text_padded + idata_padded
