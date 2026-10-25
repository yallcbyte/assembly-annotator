"""Turn raw assembly text into structured lines.

The original tool treated every line as `tokens[0] == mnemonic`, so labels,
directives and comments all came back as "Unknown instruction". This module
classifies each line first, which is most of the readability win.
"""

import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from . import registers

# `  401136:\t55 48 89 e5\tpush  %rbp`  -- objdump / gdb disassembly
OBJDUMP_RE = re.compile(
    r'^\s*(?:0x)?([0-9a-fA-F]{4,16})\s*:\s*((?:[0-9a-fA-F]{2}\s+)+)?\s*(.*)$')
# `label:` optionally followed by an instruction on the same line
LABEL_RE = re.compile(r'^([A-Za-z_.$@][\w.$@]*)\s*:\s*(.*)$')
# NASM `section .text` / GAS `.globl main` / `db 0x41`
DIRECTIVE_RE = re.compile(
    r'^\.(?!\s)|^(?:section|segment|global|globl|extern|bits|org|align|'
    r'db|dw|dd|dq|dt|resb|resw|resd|resq|times|equ|include|default|struc|endstruc)\b',
    re.IGNORECASE)
# `0000000000001129 <main>:` -- objdump's function header
OBJDUMP_FUNC_RE = re.compile(r'^\s*([0-9a-fA-F]{4,16})\s+<([^>]+)>:\s*$')
# `msg db "hello", 0` -- a named data definition, not an instruction
DATA_DEF_RE = re.compile(
    r'^([A-Za-z_.$@][\w.$@]*)\s+((?:db|dw|dd|dq|dt|resb|resw|resd|resq|equ|times)\b.*)$',
    re.IGNORECASE)
PREFIXES = {'rep', 'repe', 'repz', 'repne', 'repnz', 'lock', 'bnd', 'notrack'}

IMMEDIATE_RE = re.compile(r'^[$]?(?:0x[0-9a-fA-F]+|0b[01]+|\d+[hH]?|-\d+|#-?\d+|#0x[0-9a-fA-F]+)$')
MEMORY_RE = re.compile(r'[\[\]]|\(\s*%?\w+\s*\)|\bptr\b', re.IGNORECASE)


@dataclass
class Operand:
    text: str
    kind: str          # 'register' | 'immediate' | 'memory' | 'label' | 'unknown'
    value: Optional[int] = None   # decoded numeric value for immediates
    register: Optional[str] = None


@dataclass
class ParsedLine:
    index: int                     # 1-based line number as typed
    raw: str
    kind: str                      # instruction|label|directive|comment|blank
    label: Optional[str] = None
    mnemonic: Optional[str] = None
    prefix: Optional[str] = None
    operands: List[Operand] = field(default_factory=list)
    comment: Optional[str] = None
    address: Optional[str] = None  # from an objdump-style dump
    opcodes: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d['operands'] = [asdict(o) for o in self.operands]
        return d


def strip_comment(text: str):
    """Split a line into (code, comment). Honours ; # // and /* */."""
    in_str = None
    for i, ch in enumerate(text):
        if in_str:
            if ch == in_str and (i == 0 or text[i - 1] != '\\'):
                in_str = None
            continue
        if ch in '"\'':
            in_str = ch
            continue
        if ch == ';' or ch == '#':
            return text[:i], text[i:]
        if ch == '/' and text[i:i + 2] in ('//', '/*'):
            return text[:i], text[i:]
    return text, None


def split_operands(text: str) -> List[str]:
    """Split on commas that are not inside brackets, parens or quotes."""
    parts, depth, cur, in_str = [], 0, [], None
    for ch in text:
        if in_str:
            cur.append(ch)
            if ch == in_str:
                in_str = None
            continue
        if ch in '"\'':
            in_str = ch
            cur.append(ch)
        elif ch in '[(':
            depth += 1
            cur.append(ch)
        elif ch in '])':
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())
    return [p for p in parts if p]


def decode_immediate(text: str) -> Optional[int]:
    t = text.strip().lstrip('$#')
    neg = t.startswith('-')
    t = t.lstrip('-')
    try:
        if t.lower().startswith('0x'):
            v = int(t, 16)
        elif t.lower().startswith('0b'):
            v = int(t, 2)
        elif t.lower().endswith('h'):
            v = int(t[:-1], 16)
        elif t.isdigit():
            v = int(t, 10)
        else:
            return None
    except ValueError:
        return None
    return -v if neg else v


def classify_operand(text: str, arch: str) -> Operand:
    t = text.strip()
    if not t:
        return Operand(text=t, kind='unknown')
    if MEMORY_RE.search(t):
        return Operand(text=t, kind='memory')
    if registers.is_register(t, arch):
        return Operand(text=t, kind='register', register=registers.normalise(t))
    if IMMEDIATE_RE.match(t):
        return Operand(text=t, kind='immediate', value=decode_immediate(t))
    if t.startswith(('"', "'")):
        return Operand(text=t, kind='immediate')
    return Operand(text=t, kind='label')


def detect_arch(text: str) -> str:
    """Guess the architecture from register and mnemonic vocabulary."""
    low = text.lower()
    scores = {'x86': 0, 'arm': 0, 'mips': 0}
    scores['x86'] += len(re.findall(r'\b(?:e[a-d]x|e[sd]i|e[bs]p|r[a-d]x|r[sd]i|r[bs]p|rip|a[lh]|b[lh])\b', low))
    scores['x86'] += 2 * len(re.findall(r'\b(?:int\s+0x80|syscall|cdq|movzx|movsx|imul|jne|jmp|leave)\b', low))
    scores['arm'] += len(re.findall(r'\b(?:x\d{1,2}|w\d{1,2})\b', low))
    # Anchored to the mnemonic position: `bl` is an ARM branch but also an x86
    # register, and `ret` exists on both, so neither counts as evidence here.
    scores['arm'] += 2 * len(re.findall(
        r'(?m)^\s*(?:[0-9a-f]+:\s*)?(?:stp|ldp|bl|blr|cbz|cbnz|svc|adrp|adr|csel|cset)\b', low))
    scores['mips'] += 3 * len(re.findall(r'\$(?:zero|v[01]|a[0-3]|t\d|s\d|ra|sp|gp|fp)\b', low))
    scores['mips'] += 2 * len(re.findall(r'\b(?:lw|sw|jal|jr|addiu|beqz)\b', low))
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else 'x86'


def detect_syntax(text: str) -> str:
    """Intel (`mov eax, 1`) vs AT&T (`movl $1, %eax`)."""
    att = len(re.findall(r'%[a-z]{2,4}\b', text)) + len(re.findall(r'\$-?(?:0x)?[0-9a-f]+', text, re.I))
    intel = len(re.findall(r'\b(?:byte|word|dword|qword)\s+ptr\b', text, re.I)) + text.count('[')
    return 'att' if att > intel else 'intel'


def parse(text: str, arch: Optional[str] = None, syntax: Optional[str] = None):
    """Parse a whole listing. Returns (lines, meta)."""
    arch = arch or detect_arch(text)
    syntax = syntax or detect_syntax(text)
    lines: List[ParsedLine] = []

    for n, raw in enumerate(text.splitlines(), start=1):
        line = ParsedLine(index=n, raw=raw.rstrip(), kind='blank')
        body = raw.strip()
        if not body:
            lines.append(line)
            continue

        # objdump prints `<addr> <name>:` above each function.
        m = OBJDUMP_FUNC_RE.match(raw)
        if m:
            line.kind = 'label'
            line.address, line.label = m.group(1), m.group(2)
            lines.append(line)
            continue

        # objdump / gdb style: pull off the address and opcode bytes
        m = OBJDUMP_RE.match(raw)
        if m and m.group(3).strip() and not LABEL_RE.match(body):
            line.address = m.group(1)
            line.opcodes = (m.group(2) or '').strip() or None
            body = m.group(3).strip()

        code, comment = strip_comment(body)
        if comment:
            line.comment = comment.lstrip(';#/* ').strip()
        code = code.strip()

        if not code:
            line.kind = 'comment'
            lines.append(line)
            continue

        # A trailing colon makes it a label, even when it starts with a dot
        # (`.denied:`, `.L2:`). Directives such as `.globl main` have no colon.
        m = LABEL_RE.match(code)
        if m:
            line.label = m.group(1)
            line.kind = 'label'
            code = m.group(2).strip()
            if not code:
                lines.append(line)
                continue

        # `msg db "hi", 0` names the data it defines -- record the symbol as a
        # label so branches and address references can resolve against it.
        m = DATA_DEF_RE.match(code)
        if m and not DIRECTIVE_RE.match(code):
            line.label = line.label or m.group(1)
            code = m.group(2)

        if DIRECTIVE_RE.match(code):
            line.kind = 'directive'
            line.mnemonic = code.split()[0].lower()
            line.operands = [classify_operand(p, arch)
                             for p in split_operands(code.split(None, 1)[1])] \
                if len(code.split(None, 1)) > 1 else []
            lines.append(line)
            continue

        tokens = code.split(None, 1)
        mnemonic = tokens[0].lower()

        # A leading rep/lock prefix is recorded separately so the real
        # mnemonic still gets explained.
        if mnemonic in PREFIXES and len(tokens) > 1:
            line.prefix = mnemonic
            tokens = tokens[1].split(None, 1)
            mnemonic = tokens[0].lower()

        line.kind = 'instruction'
        line.mnemonic = mnemonic
        if len(tokens) > 1:
            ops = split_operands(tokens[1])
            # AT&T lists source first; flip so downstream code always sees
            # destination-first (Intel) order.
            if syntax == 'att' and len(ops) == 2:
                ops = [ops[1], ops[0]]
            line.operands = [classify_operand(o, arch) for o in ops]
        lines.append(line)

    meta = {
        'arch': arch,
        'syntax': syntax,
        'total_lines': len(lines),
        'instruction_count': sum(1 for l in lines if l.kind == 'instruction'),
        'label_count': sum(1 for l in lines if l.label),
    }
    return lines, meta
