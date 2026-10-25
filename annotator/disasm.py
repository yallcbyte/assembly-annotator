"""Raw bytes in, assembly text out.

The annotator reads assembly *text*, which you normally only have once you
have already run a disassembler. This module closes that gap: paste hex, an
xxd dump or an ELF file and it produces a listing in the objdump format
`parser.py` already understands.

Capstone is an optional dependency. Everything here degrades to a clear
error when it is missing rather than breaking the rest of the app.
"""

import re
import struct
from typing import NamedTuple, Optional

try:
    import capstone
    AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without capstone
    capstone = None
    AVAILABLE = False


class DisasmError(ValueError):
    """Raised for input we cannot turn into instructions."""


MAX_BYTES = 256 * 1024

# (arch, bits) -> (capstone arch, capstone mode)
_MODES = {
    ('x86', 16): ('CS_ARCH_X86', 'CS_MODE_16'),
    ('x86', 32): ('CS_ARCH_X86', 'CS_MODE_32'),
    ('x86', 64): ('CS_ARCH_X86', 'CS_MODE_64'),
    ('arm', 32): ('CS_ARCH_ARM', 'CS_MODE_ARM'),
    ('arm', 64): ('CS_ARCH_ARM64', 'CS_MODE_ARM'),
    ('thumb', 32): ('CS_ARCH_ARM', 'CS_MODE_THUMB'),
    ('mips', 32): ('CS_ARCH_MIPS', 'CS_MODE_MIPS32'),
    ('mips', 64): ('CS_ARCH_MIPS', 'CS_MODE_MIPS64'),
}

# ELF e_machine -> (our arch name, bits)
_ELF_MACHINES = {
    3: ('x86', 32), 62: ('x86', 64), 40: ('arm', 32),
    183: ('arm', 64), 8: ('mips', 32),
}


class Binary(NamedTuple):
    data: bytes
    base: int
    arch: Optional[str]
    bits: Optional[int]
    source: str          # 'raw' | 'elf'
    note: str = ''


# ---- hex / dump parsing ------------------------------------------------

# `0000:` / `00000000:` -- an offset column that ends in a colon (xxd, objdump)
_COLON_OFFSET_RE = re.compile(r'^\s*(?:0x)?[0-9a-fA-F]{4,16}:\s*')
# `00000000  ` -- hexdump -C's offset column, which has no colon
_BARE_OFFSET_RE = re.compile(r'^\s*[0-9a-fA-F]{6,16}(?:\s+|$)')
# the `|.Ph//sh|` gutter hexdump -C prints on the right
_GUTTER_RE = re.compile(r'\|[^|]*\|\s*$')
# a `b'...'` / `"..."` wrapper from a Python repr or a C string literal
_QUOTE_WRAP_RE = re.compile(r'^\s*[bBuU]?["\'](.*)["\']\s*$', re.DOTALL)
# `\x41` style escapes, as pasted from C or Python source
_ESCAPE_RE = re.compile(r'\\x([0-9a-fA-F]{2})')


def _strip_ascii_column(line: str) -> str:
    """xxd separates its ASCII column with two or more spaces."""
    return re.split(r'\s{2,}', line.strip(), maxsplit=1)[0]


def parse_hex(text: str) -> bytes:
    r"""Accept hex in whatever shape it was copied in.

    Handles plain hex (`31c050`), spaced bytes (`31 c0 50`), C escapes
    (`\x31\xc0`), comma-separated literals (`0x31, 0xc0`), Python/C string
    literals, `xxd` output and `hexdump -C` output.
    """
    if not text or not text.strip():
        raise DisasmError('No bytes provided.')

    # `\xNN` escapes are unambiguous, so when they are present take only
    # those and ignore any surrounding declaration (`char sc[] = "...";`).
    escapes = _ESCAPE_RE.findall(text)
    if escapes:
        data = bytes(int(h, 16) for h in escapes)
        if len(data) > MAX_BYTES:
            raise DisasmError(f'{len(data)} bytes is over the {MAX_BYTES} byte limit.')
        return data

    wrapped = _QUOTE_WRAP_RE.match(text)
    if wrapped:
        text = wrapped.group(1)

    # Decide the format once for the whole block rather than per line, so a
    # plain hex blob is never mistaken for a dump with an offset column.
    lines = [l for l in text.splitlines() if l.strip()]
    has_gutter = any(_GUTTER_RE.search(l) for l in lines)
    has_colon_offset = any(_COLON_OFFSET_RE.match(l) for l in lines)

    cleaned = []
    for line in lines:
        if has_gutter:
            gutter = _GUTTER_RE.search(line)
            if gutter:
                line = line[:gutter.start()]
            line = _BARE_OFFSET_RE.sub('', line, count=1)
        elif has_colon_offset:
            line = _COLON_OFFSET_RE.sub('', line, count=1)
            line = _strip_ascii_column(line)
        if line.strip():
            cleaned.append(line)

    blob = '\n'.join(cleaned)
    # Normalise the separators people actually paste.
    blob = blob.replace('\\x', ' ').replace('0x', ' ').replace('0X', ' ')
    # Braces, brackets and quotes show up when pasting a C array or a literal.
    blob = re.sub(r'[,;{}()\[\]"\'\s]+', ' ', blob).strip()

    compact = blob.replace(' ', '')
    if not compact:
        raise DisasmError('No hex bytes found in that input.')
    stray = set(compact) - set('0123456789abcdefABCDEF')
    if stray:
        shown = ', '.join(sorted(repr(c) for c in stray)[:5])
        raise DisasmError(f'Input is not pure hex \u2014 unexpected character(s): {shown}')
    if len(compact) % 2:
        raise DisasmError(f'Hex input has an odd number of digits ({len(compact)}); '
                          'bytes come in pairs.')

    data = bytes.fromhex(compact)
    if not data:
        raise DisasmError('No hex bytes found in that input.')
    if len(data) > MAX_BYTES:
        raise DisasmError(f'{len(data)} bytes is over the {MAX_BYTES} byte limit.')
    return data


# ---- ELF -----------------------------------------------------------------

def looks_like_elf(data: bytes) -> bool:
    return data[:4] == b'\x7fELF'


def extract_elf_text(data: bytes) -> Binary:
    """Pull the executable section out of an ELF image.

    Prefers `.text`; falls back to the first executable section, then to the
    whole file if the section table is unusable.
    """
    if len(data) < 52 or not looks_like_elf(data):
        raise DisasmError('Not an ELF file.')

    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise DisasmError('Unrecognised ELF class.')
    bits64 = ei_class == 2
    endian = '<' if ei_data == 1 else '>'

    try:
        machine = struct.unpack_from(endian + 'H', data, 18)[0]
        if bits64:
            e_shoff = struct.unpack_from(endian + 'Q', data, 0x28)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + 'HHH', data, 0x3A)
        else:
            e_shoff = struct.unpack_from(endian + 'I', data, 0x20)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + 'HHH', data, 0x2E)
    except struct.error:
        raise DisasmError('ELF header is truncated.')

    arch, bits = _ELF_MACHINES.get(machine, (None, 64 if bits64 else 32))

    def whole_file(note):
        return Binary(data, 0, arch, bits, 'elf', note)

    if not e_shoff or not e_shnum or e_shoff + e_shnum * e_shentsize > len(data):
        return whole_file('No usable section table; disassembling the whole file.')

    def section(i):
        off = e_shoff + i * e_shentsize
        if bits64:
            name, _type, flags, addr, offset, size = struct.unpack_from(
                endian + 'IIQQQQ', data, off)
        else:
            name, _type, flags, addr, offset, size = struct.unpack_from(
                endian + 'IIIIII', data, off)
        return {'name_off': name, 'flags': flags, 'addr': addr,
                'offset': offset, 'size': size}

    try:
        sections = [section(i) for i in range(e_shnum)]
    except struct.error:
        return whole_file('Section table is truncated; disassembling the whole file.')

    names = {}
    if e_shstrndx < len(sections):
        strtab = sections[e_shstrndx]
        base = strtab['offset']
        for idx, sec in enumerate(sections):
            start = base + sec['name_off']
            end = data.find(b'\x00', start)
            if 0 <= start <= len(data) and end != -1:
                names[idx] = data[start:end].decode('utf-8', 'replace')

    SHF_EXECINSTR = 0x4
    chosen = None
    for idx, sec in enumerate(sections):
        if names.get(idx) == '.text' and sec['size']:
            chosen = (idx, sec)
            break
    if chosen is None:
        for idx, sec in enumerate(sections):
            if sec['flags'] & SHF_EXECINSTR and sec['size']:
                chosen = (idx, sec)
                break
    if chosen is None:
        return whole_file('No executable section found; disassembling the whole file.')

    idx, sec = chosen
    start, end = sec['offset'], sec['offset'] + sec['size']
    if end > len(data):
        return whole_file('Section extends past end of file; disassembling the whole file.')

    return Binary(data[start:end], sec['addr'], arch, bits, 'elf',
                  f'Extracted section {names.get(idx, "?")} '
                  f'({sec["size"]} bytes) at 0x{sec["addr"]:x}.')


def load(data: bytes) -> Binary:
    """Wrap raw bytes, unwrapping an ELF container if there is one."""
    if looks_like_elf(data):
        return extract_elf_text(data)
    if data[:2] == b'MZ':
        raise DisasmError('PE/EXE files are not supported yet — extract the '
                          '.text section first, or paste its bytes as hex.')
    return Binary(data, 0, None, None, 'raw')


# ---- disassembly ---------------------------------------------------------

def disassemble(data: bytes, arch: str = 'x86', bits: int = 32,
                base: int = 0x1000, syntax: str = 'intel') -> dict:
    """Disassemble bytes into objdump-style text the parser can read."""
    if not AVAILABLE:
        raise DisasmError('Disassembly needs the `capstone` package: '
                          'pip install capstone')
    if not data:
        raise DisasmError('No bytes to disassemble.')
    if len(data) > MAX_BYTES:
        raise DisasmError(f'{len(data)} bytes is over the {MAX_BYTES} byte limit.')

    key = (arch, bits)
    if key not in _MODES:
        raise DisasmError(f'No disassembler for {arch}/{bits}-bit.')
    cs_arch, cs_mode = _MODES[key]

    md = capstone.Cs(getattr(capstone, cs_arch), getattr(capstone, cs_mode))
    md.skipdata = True  # keep going past bytes that are not code
    if arch == 'x86' and syntax == 'att':
        md.syntax = capstone.CS_OPT_SYNTAX_ATT

    lines, count, bad = [], 0, 0
    last_end = base
    for insn in md.disasm(data, base):
        opcodes = ' '.join(f'{b:02x}' for b in insn.bytes)
        text = insn.mnemonic
        if insn.op_str:
            text += ' ' + insn.op_str
        if insn.mnemonic == '.byte':
            bad += 1
        lines.append(f'{insn.address:08x}:\t{opcodes}\t{text}')
        last_end = insn.address + insn.size
        count += 1

    if not count:
        raise DisasmError('Capstone produced no instructions from those bytes. '
                          'Check the architecture and bit width.')

    undecoded = base + len(data) - last_end
    return {
        'text': '\n'.join(lines),
        'instructions': count,
        'bytes': len(data),
        'undecoded_bytes': max(0, undecoded),
        'skipped_data': bad,
        'arch': arch,
        'bits': bits,
        'base': base,
    }
