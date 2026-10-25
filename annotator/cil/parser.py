"""Parse ildasm / ILSpy / dnSpy IL listings.

CIL text differs from native assembly in ways that matter:
  * every instruction carries an `IL_xxxx:` offset, which doubles as a label
  * an instruction has at most one operand, but that operand is a method
    signature full of commas, so it must never be comma-split
  * `.method`, `.locals init` and `.maxstack` carry the context that makes
    the body readable
"""

import re
from typing import List, Optional, Tuple

from ..parser import Operand, ParsedLine
from . import isa

# `IL_0012:` -- the offset label every instruction carries
OFFSET_RE = re.compile(r'^\s*(IL_[0-9A-Fa-f]{2,8})\s*:\s*(.*)$')
# `.method public hidebysig static void Main(string[] args) cil managed`
METHOD_RE = re.compile(r'^\s*\.method\b(?P<rest>.*)$', re.IGNORECASE)
# `.locals init ([0] string url, [1] int32 i)`
LOCALS_RE = re.compile(r'^\s*\.locals\b\s*(?:init)?\s*\((?P<body>.*)\)\s*$',
                       re.IGNORECASE | re.DOTALL)
MAXSTACK_RE = re.compile(r'^\s*\.maxstack\s+(\d+)', re.IGNORECASE)
DIRECTIVE_RE = re.compile(r'^\s*\.(\w+)', re.IGNORECASE)
# `[0] string url` or `string url` or just `int32`
LOCAL_SLOT_RE = re.compile(r'^\s*(?:\[(?P<slot>\d+)\]\s*)?(?P<type>.+?)(?:\s+(?P<name>[\w$<>`]+))?\s*$')
SWITCH_RE = re.compile(r'^\s*\((?P<targets>.*)\)\s*$', re.DOTALL)

STRUCTURAL = {'{', '}', '(', ')'}

# Scope keywords that introduce exception-handling regions.
REGION_WORDS = {'.try', 'catch', 'finally', 'filter', 'fault'}


def _strip_comment(text: str) -> Tuple[str, Optional[str]]:
    """Split off a // or /* comment, respecting string literals."""
    in_str = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == '\\':
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == '/' and text[i:i + 2] in ('//', '/*'):
            return text[:i], text[i:]
        i += 1
    return text, None


def split_locals(body: str) -> List[dict]:
    """Turn a `.locals init (...)` body into slot records."""
    parts, depth, cur = [], 0, []
    for ch in body:
        if ch in '<[(':
            depth += 1
        elif ch in '>])':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())

    slots = []
    for n, part in enumerate(p for p in parts if p.strip()):
        m = LOCAL_SLOT_RE.match(part)
        if not m:
            slots.append({'slot': n, 'type': part.strip(), 'name': None})
            continue
        slot = int(m.group('slot')) if m.group('slot') is not None else n
        type_text = (m.group('type') or '').strip()
        name = m.group('name')
        # `class [mscorlib]System.String` has no name; the last word is the type.
        if name and type_text.endswith(('class', 'valuetype')):
            type_text, name = f'{type_text} {name}', None
        slots.append({'slot': slot, 'type': type_text, 'name': name})
    return slots


def classify_operand(opcode: str, text: str) -> Operand:
    """CIL operands are tokens, not registers."""
    t = text.strip()
    if not t:
        return Operand(text=t, kind='unknown')
    if t.startswith('"'):
        return Operand(text=t, kind='string')
    if re.match(r'^IL_[0-9A-Fa-f]+$', t):
        return Operand(text=t, kind='label')
    if '::' in t:
        kind = 'method' if '(' in t else 'field'
        return Operand(text=t, kind=kind)
    if re.match(r'^-?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)$', t):
        value = None
        try:
            value = int(t, 0)
        except ValueError:
            pass
        return Operand(text=t, kind='immediate', value=value)
    if re.match(r'^V_\d+$', t) or re.match(r'^\d+$', t):
        return Operand(text=t, kind='slot')
    return Operand(text=t, kind='type')


def looks_like_cil(text: str) -> int:
    """Score how strongly this text looks like a CIL listing."""
    score = 0
    score += 3 * len(re.findall(r'^\s*IL_[0-9A-Fa-f]{2,8}\s*:', text, re.MULTILINE))
    score += 4 * len(re.findall(r'^\s*\.(?:method|maxstack|locals|entrypoint|assembly)\b',
                                text, re.MULTILINE | re.IGNORECASE))
    score += 3 * len(re.findall(r'\b(?:callvirt|ldstr|ldarg\.\d|stloc\.\d|ldloc\.\d|'
                                r'newobj|ldsfld|box|unbox\.any|isinst|castclass)\b', text))
    score += 2 * len(re.findall(r'\[(?:mscorlib|System[\w.]*|netstandard)\]', text))
    score += 2 * len(re.findall(r'\bcil\s+managed\b', text))
    return score


def parse(text: str):
    """Parse a CIL listing into ParsedLine records plus method context."""
    lines: List[ParsedLine] = []
    methods: List[dict] = []
    locals_table: List[dict] = []
    maxstack: Optional[int] = None
    current_method: Optional[dict] = None
    pending_locals: Optional[List[str]] = None

    for n, raw in enumerate(text.splitlines(), start=1):
        line = ParsedLine(index=n, raw=raw.rstrip(), kind='blank')
        body = raw.strip()

        # A `.locals init (` list may wrap across several lines.
        if pending_locals is not None:
            pending_locals.append(body)
            joined = ' '.join(pending_locals)
            line.kind = 'directive'
            line.mnemonic = '.locals'
            if joined.count('(') <= joined.count(')'):
                m = LOCALS_RE.match(joined)
                if m:
                    locals_table = split_locals(m.group('body'))
                pending_locals = None
            lines.append(line)
            continue

        if not body:
            lines.append(line)
            continue

        code, comment = _strip_comment(body)
        if comment:
            line.comment = comment.lstrip('/* ').strip()
        code = code.strip()

        if not code:
            line.kind = 'comment'
            lines.append(line)
            continue

        if code in STRUCTURAL:
            line.kind = 'blank'
            lines.append(line)
            continue

        m = METHOD_RE.match(code)
        if m:
            line.kind = 'directive'
            line.mnemonic = '.method'
            current_method = {'line': n, 'declaration': code, 'name': _method_name(code)}
            methods.append(current_method)
            line.label = current_method['name']
            locals_table, maxstack = [], None
            lines.append(line)
            continue

        m = MAXSTACK_RE.match(code)
        if m:
            maxstack = int(m.group(1))
            line.kind = 'directive'
            line.mnemonic = '.maxstack'
            lines.append(line)
            continue

        if re.match(r'^\s*\.locals\b', code, re.IGNORECASE):
            line.kind = 'directive'
            line.mnemonic = '.locals'
            m = LOCALS_RE.match(code)
            if m:
                locals_table = split_locals(m.group('body'))
            elif code.count('(') > code.count(')'):
                pending_locals = [code]
            lines.append(line)
            continue

        # `IL_0007:` prefix, which we keep as a label so branches resolve.
        m = OFFSET_RE.match(code)
        if m:
            line.label = m.group(1)
            line.address = m.group(1)[3:]
            code = m.group(2).strip()
            if not code:
                line.kind = 'label'
                lines.append(line)
                continue

        first_word = code.split()[0].lower().rstrip(':')
        if code.startswith('.') or first_word in REGION_WORDS:
            line.kind = 'directive'
            line.mnemonic = first_word
            lines.append(line)
            continue

        tokens = code.split(None, 1)
        opcode = tokens[0].lower()
        rest = tokens[1].strip() if len(tokens) > 1 else ''

        # Prefixes such as `constrained.` take an operand and the real
        # instruction follows, often on the next line.
        line.kind = 'instruction'
        line.mnemonic = opcode
        if rest:
            if opcode == 'switch':
                sm = SWITCH_RE.match(rest)
                targets = sm.group('targets') if sm else rest
                line.operands = [classify_operand(opcode, t)
                                 for t in targets.split(',') if t.strip()]
            else:
                line.operands = [classify_operand(opcode, rest)]
        lines.append(line)

    meta = {
        'arch': 'cil',
        'syntax': 'ildasm',
        'total_lines': len(lines),
        'instruction_count': sum(1 for l in lines if l.kind == 'instruction'),
        'label_count': sum(1 for l in lines if l.label),
        'methods': methods,
        'locals': locals_table,
        'maxstack': maxstack,
    }
    return lines, meta


def _method_name(declaration: str) -> Optional[str]:
    """Pull `Main` out of a `.method ... void Main(string[]) cil managed` line."""
    m = re.search(r'([\w.`<>$]+)\s*\(', declaration)
    return m.group(1) if m else None
