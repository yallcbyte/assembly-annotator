"""Undo two common .NET obfuscations well enough to read the code.

1. Invisible names. ConfuserEx and friends rename everything to runs of
   zero-width and bidirectional-override characters (U+200B, U+202E, ...).
   They display as nothing, or reorder the text around them. NameAliaser
   swaps each distinct one for a stable alias: obf_1, obf_2, ...

2. Control-flow flattening. A method's statements are cut into the cases of
   a switch inside an endless loop, and a scrambled state variable decides
   which case runs next:

       uint num = 3442226333U;
       for (;;) {
           switch ((num2 = (num ^ 2399871976U)) % 9U) {
           case 8U: ...; num = (num2 * 884458529U ^ 1161631898U); continue;
           ...

   The constants are all in the listing, so the real order can be computed.
   unflatten() does that, following both sides of every condition.
"""

import re
from typing import Dict, List, Optional

M32 = 0xFFFFFFFF

# Zero-width, bidi-control and other invisible formatting characters.
_INVISIBLE = '​-‏‪-‮⁠-⁤⁦-⁯﻿'
_RAW_RUN = f'[{_INVISIBLE}]'
# dnSpy prints the same characters escaped: ‮⁭...
_ESC_ONE = r'\\u(?:200[b-fB-F]|202[a-eA-E]|206[0-46-9a-fA-F]|[fF][eE][fF][fF])'
_NAME_RE = re.compile(rf'(?:{_RAW_RUN}|{_ESC_ONE}){{2,}}')
BIDI_RE = re.compile('[‪-‮⁦-⁩]')


class NameAliaser:
    """Gives each distinct invisible name a readable, stable alias."""

    def __init__(self, prefix: str = 'obf_'):
        self.prefix = prefix
        self.aliases: Dict[str, str] = {}

    @staticmethod
    def _canonical(name: str) -> str:
        """Escaped and raw spellings of the same name share one alias."""
        return re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), name)

    def alias(self, name: str) -> str:
        key = self._canonical(name)
        if key not in self.aliases:
            self.aliases[key] = f'{self.prefix}{len(self.aliases) + 1}'
        return self.aliases[key]

    def sub(self, text: str) -> str:
        if not text:
            return text
        return _NAME_RE.sub(lambda m: self.alias(m.group(0)), text)

    def describe(self) -> List[dict]:
        out = []
        for name, alias in self.aliases.items():
            kinds = sorted({_char_kind(c) for c in name})
            out.append({'alias': alias, 'length': len(name), 'kinds': kinds,
                        'sample': ' '.join(f'U+{ord(c):04X}' for c in name[:4])})
        return out


def _char_kind(c: str) -> str:
    cp = ord(c)
    if cp in (0x202E, 0x202D, 0x202A, 0x202B, 0x202C) or 0x2066 <= cp <= 0x2069:
        return 'bidi control'
    if cp in (0x200B, 0x200C, 0x200D, 0xFEFF):
        return 'zero-width'
    if cp in (0x200E, 0x200F):
        return 'direction mark'
    return 'invisible formatting'


def neutralise_bidi(text: str) -> str:
    """Make bidi overrides visible so they cannot reorder displayed text."""
    return BIDI_RE.sub(lambda m: f'⟨U+{ord(m.group(0)):04X}⟩', text)


# ---- a tiny, safe evaluator for uint32 state arithmetic ---------------------

class _ExprError(ValueError):
    pass


_TOKEN_RE = re.compile(r'\s*(?:(?P<num>\d+)[uUlL]*|(?P<id>[A-Za-z_]\w*)|(?P<op>[-+*^&|%()]))')


def _tokens(expr: str):
    pos, out = 0, []
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m or m.end() == pos:
            if expr[pos:].strip() == '':
                break
            raise _ExprError(f'cannot read {expr[pos:pos + 12]!r}')
        pos = m.end()
        if m.group('num'):
            out.append(('num', int(m.group('num'))))
        elif m.group('id'):
            out.append(('id', m.group('id')))
        else:
            out.append(('op', m.group('op')))
    return out


def evaluate(expr: str, env: Dict[str, int]) -> int:
    """C# precedence: * % > + - > & > ^ > |, wrapped to uint32."""
    toks = _tokens(expr)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else (None, None)

    def take():
        tok = peek()
        pos[0] += 1
        return tok

    def primary():
        kind, val = take()
        if kind == 'num':
            return val & M32
        if kind == 'id':
            if val not in env:
                raise _ExprError(f'unknown name {val}')
            return env[val] & M32
        if (kind, val) == ('op', '('):
            v = level(0)
            if take() != ('op', ')'):
                raise _ExprError('unbalanced parentheses')
            return v
        if (kind, val) == ('op', '-'):
            return (-primary()) & M32
        raise _ExprError(f'unexpected {val!r}')

    levels = [('|',), ('^',), ('&',), ('+', '-'), ('*', '%')]

    def level(i):
        if i == len(levels):
            return primary()
        v = level(i + 1)
        while peek()[0] == 'op' and peek()[1] in levels[i]:
            op = take()[1]
            r = level(i + 1)
            if op == '|':
                v |= r
            elif op == '^':
                v ^= r
            elif op == '&':
                v &= r
            elif op == '+':
                v += r
            elif op == '-':
                v -= r
            elif op == '*':
                v *= r
            elif op == '%':
                if r == 0:
                    raise _ExprError('modulo by zero')
                v %= r
            v &= M32
        return v

    result = level(0)
    if pos[0] != len(toks):
        raise _ExprError('trailing input')
    return result


def _split_ternaries(expr: str):
    """Replace each `(cond ? a : b)` with __T0__, __T1__..., returning the parts."""
    ternaries = []
    while True:
        q = _find_outside_strings(expr, '?')
        if q < 0:
            return expr, ternaries
        depth, start = 0, -1
        for i in range(q - 1, -1, -1):
            ch = expr[i]
            if ch == ')':
                depth += 1
            elif ch == '(':
                if depth == 0:
                    start = i
                    break
                depth -= 1
        if start < 0:
            raise _ExprError('ternary without enclosing parentheses')
        depth, colon, end = 0, -1, -1
        for i in range(q + 1, len(expr)):
            ch = expr[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                if depth == 0:
                    end = i
                    break
                depth -= 1
            elif ch == ':' and depth == 0 and colon < 0:
                colon = i
        if colon < 0 or end < 0:
            raise _ExprError('malformed ternary')
        cond = expr[start + 1:q].strip()
        yes, no = expr[q + 1:colon].strip(), expr[colon + 1:end].strip()
        name = f'__T{len(ternaries)}__'
        cond, negated = _positive(_tidy_condition(cond))
        if negated:
            yes, no = no, yes
        ternaries.append({'name': name, 'cond': cond, 'yes': yes, 'no': no})
        expr = expr[:start] + name + expr[end + 1:]


def _find_outside_strings(text: str, ch: str) -> int:
    in_str = False
    i = 0
    while i < len(text):
        c = text[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == ch:
            return i
        i += 1
    return -1


def _tidy_condition(cond: str) -> str:
    cond = re.sub(r'\s+', ' ', cond).strip()
    while cond.startswith('(') and cond.endswith(')') and _balanced(cond[1:-1]):
        cond = cond[1:-1].strip()
    return cond


def _positive(cond: str):
    """`!x` -> (`x`, True) so a condition never reads as a double negative."""
    if cond.startswith('!') and not cond.startswith('!='):
        inner = _tidy_condition(cond[1:])
        if _balanced(inner):
            return inner, True
    return cond, False


def _balanced(text: str) -> bool:
    depth = 0
    for c in text:
        depth += (c == '(') - (c == ')')
        if depth < 0:
            return False
    return depth == 0


# ---- flattening -----------------------------------------------------------------

_DISPATCH_RE = re.compile(
    r'switch\s*\(\s*\(\s*(?P<s2>\w+)\s*=\s*\(?\s*(?P<s>\w+)\s*\^\s*(?P<key>\d+)[uU]?\s*\)?\s*\)'
    r'\s*%\s*(?P<n>\d+)[uU]?\s*\)')
_CASE_RE = re.compile(r'^\s*case\s+(\d+)[uU]?\s*:')
_GOTO_RE = re.compile(r'\bgoto\s+(\w+)\s*;')


def find_dispatchers(lines: List[str]) -> List[int]:
    return [i for i, l in enumerate(lines) if _DISPATCH_RE.search(l)]


def unflatten(lines: List[str], dispatch_index: int, max_paths: int = 8,
              max_steps: int = 64) -> Optional[dict]:
    """Recover the execution order of one flattened switch, or None."""
    m = _DISPATCH_RE.search(lines[dispatch_index])
    if not m:
        return None
    s, s2 = m.group('s'), m.group('s2')
    key, modulus = int(m.group('key')), int(m.group('n'))
    if modulus == 0:
        return None

    initial = None
    assign_re = re.compile(rf'(?:\buint\s+)?\b{re.escape(s)}\s*=\s*(\d+)[uU]?\s*;')
    for i in range(dispatch_index - 1, max(-1, dispatch_index - 40), -1):
        a = assign_re.search(lines[i])
        if a:
            initial = int(a.group(1))
            break
    if initial is None:
        return None

    cases = _collect_cases(lines, dispatch_index)
    if not cases:
        return None
    transition_re = re.compile(rf'(?:^|[;{{}}])\s*{re.escape(s)}\s*=\s*')
    for case in cases.values():
        joined = ' '.join(lines[i].strip() for i in case['lines'])
        case['goto'] = bool(_GOTO_RE.search(joined))
        case['exits'] = bool(re.search(r'\breturn\b|\bbreak\s*;', joined)) and not case['goto']
        case['expr'] = None
        t = transition_re.search(joined)
        if t:
            end = _statement_end(joined, t.end())
            case['expr'] = joined[t.end():end].strip()
        case['statements'] = _case_statements(lines, case['lines'], s, s2)

    paths, reached = [], set()

    def walk(state, order, conditions, steps):
        if len(paths) >= max_paths:
            return
        seen = set()
        while steps < max_steps:
            if state in seen:
                paths.append({'order': order, 'conditions': conditions, 'end': 'loop'})
                return
            seen.add(state)
            v2 = (state ^ key) & M32
            label = v2 % modulus
            if label not in cases:
                paths.append({'order': order, 'conditions': conditions, 'end': 'exit',
                              'exit_state': label})
                return
            order = order + [label]
            reached.add(label)
            case = cases[label]
            steps += 1
            if case['goto']:
                state = initial
                continue
            if case['exits'] or case['expr'] is None:
                paths.append({'order': order, 'conditions': conditions, 'end': 'exit'})
                return
            try:
                expr, ternaries = _split_ternaries(case['expr'])
            except _ExprError:
                paths.append({'order': order, 'conditions': conditions, 'end': 'unknown'})
                return
            if len(ternaries) > 3:
                paths.append({'order': order, 'conditions': conditions, 'end': 'unknown'})
                return
            branches = []
            for mask in range(2 ** len(ternaries)):
                env = {s: state, s2: v2}
                chosen = []
                try:
                    for bit, t in enumerate(ternaries):
                        taken = not (mask >> bit) & 1
                        env[t['name']] = evaluate(t['yes'] if taken else t['no'], env)
                        chosen.append({'state': label, 'condition': t['cond'], 'value': taken})
                    branches.append((evaluate(expr, env), chosen))
                except _ExprError:
                    paths.append({'order': order, 'conditions': conditions, 'end': 'unknown'})
                    return
            if len(branches) == 1:
                state = branches[0][0]
                continue
            for next_state, chosen in branches:
                walk(next_state, order, conditions + chosen, steps)
            return
        paths.append({'order': order, 'conditions': conditions, 'end': 'limit'})

    walk(initial, [], [], 0)
    if not paths:
        return None
    return {
        'line': dispatch_index,
        'state_variable': s,
        'key': key,
        'modulus': modulus,
        'initial': initial,
        'cases': {k: {'line': v['line'], 'statements': v['statements']} for k, v in cases.items()},
        'paths': paths,
        'unreached': sorted(set(cases) - reached),
    }


def _statement_end(text: str, start: int) -> int:
    depth, in_str, i = 0, False, start
    while i < len(text):
        c = text[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ';' and depth <= 0:
            return i
        i += 1
    return len(text)


def _collect_cases(lines, dispatch_index):
    """Map case label -> its line numbers, staying inside the switch body."""
    depth, started, cases, current = 0, False, {}, None
    for i in range(dispatch_index, len(lines)):
        text = lines[i]
        code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)
        if not started:
            if '{' in code:
                started = True
                depth = code.count('{') - code.count('}')
            continue
        m = _CASE_RE.match(text)
        if m and depth == 1:
            current = int(m.group(1))
            cases[current] = {'line': i, 'lines': []}
        elif current is not None:
            cases[current]['lines'].append(i)
        depth += code.count('{') - code.count('}')
        if depth <= 0:
            break
    return cases


def _case_statements(lines, indexes, s, s2):
    """The real work a case does: everything except the dispatcher plumbing.

    Braces at parenthesis depth 0 are block braces and are dropped; braces
    inside a call are array or object initialisers and are kept.
    """
    text = ' '.join(lines[i].strip() for i in indexes)
    stmts, cur, depth, in_str = [], [], 0, False
    for i, c in enumerate(text):
        if in_str:
            cur.append(c)
            if c == '"' and text[i - 1] != '\\':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        elif c in '{}' and depth <= 0:
            cur.append(' ')
            continue
        cur.append(c)
        if c == ';' and depth <= 0:
            stmts.append(''.join(cur))
            cur = []
    out = []
    declaration_only = re.compile(r'^[A-Za-z_][\w.<>\[\],]*\s+[A-Za-z_]\w*\s*;$')
    for stmt in stmts:
        stmt = re.sub(r'\s+', ' ', stmt).strip()
        stmt = re.sub(r'\{\s+', '{ ', re.sub(r'\s+\}', ' }', stmt))
        if not stmt or stmt == 'continue;' or declaration_only.match(stmt):
            continue
        if re.match(rf'^{re.escape(s)}\s*=', stmt):
            continue
        out.append(stmt)
    return out
