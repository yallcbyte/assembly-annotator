"""Explain CIL, tracking the evaluation stack.

CIL is a stack machine, so an instruction's operands are whatever earlier
instructions pushed. Modelling that stack is what turns

    ldstr    "http://host/p.bin"
    callvirt instance string WebClient::DownloadString(string)

into "Download a URL as text, passing the literal “http://host/p.bin”."
"""

import re
from typing import Any, List, NamedTuple, Optional

from . import isa


class Value(NamedTuple):
    """One slot on the modelled evaluation stack."""
    kind: str              # string|const|local|arg|field|object|result|address|unknown
    text: str              # how to name it in a sentence
    origin: Optional[int] = None   # line that pushed it
    literal: Any = None    # decoded constant, when we have one


UNKNOWN = Value('unknown', 'a value')

# Short-form opcodes that carry their operand in the name.
_LD_ARG_N = re.compile(r'^ldarg\.(\d)$')
_LD_LOC_N = re.compile(r'^ldloc\.(\d)$')
_ST_LOC_N = re.compile(r'^stloc\.(\d)$')
_LDC_I4_N = re.compile(r'^ldc\.i4\.(m1|M1|\d)$')


def _unquote(text: str) -> str:
    t = text.strip()
    if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
        return t[1:-1]
    return t


class CilExplainer:
    def __init__(self, locals_table=None, maxstack=None, verbosity='normal'):
        self.locals = {l['slot']: l for l in (locals_table or [])}
        self.maxstack = maxstack
        self.verbosity = verbosity
        self.stack: List[Value] = []
        self.local_values = {}
        self.local_reads = {}
        self.local_writes = {}
        self.max_seen = 0
        self.underflowed = False

    # -- stack helpers -------------------------------------------------
    def _push(self, value: Value):
        self.stack.append(value)
        self.max_seen = max(self.max_seen, len(self.stack))

    def _pop(self, n=1) -> List[Value]:
        """Pop n values, oldest first. Records underflow instead of failing."""
        if n <= 0:
            return []
        if len(self.stack) < n:
            self.underflowed = True
            taken = self.stack[:]
            self.stack = []
            return [UNKNOWN] * (n - len(taken)) + taken
        taken = self.stack[-n:]
        del self.stack[-n:]
        return taken

    def local_name(self, slot: int) -> str:
        info = self.locals.get(slot)
        if info and info.get('name'):
            return f"{info['name']} (V_{slot})"
        return f'V_{slot}'

    # -- naming --------------------------------------------------------
    def describe(self, value: Value) -> str:
        return value.text

    def _value_for_push(self, line, entry) -> Value:
        op = line.operands[0] if line.operands else None
        m = _LD_LOC_N.match(line.mnemonic or '')
        if m or (line.mnemonic in ('ldloc', 'ldloc.s') and op):
            slot = int(m.group(1)) if m else self._slot_of(op)
            known = self.local_values.get(slot)
            if known is not None:
                return known._replace(origin=line.index)
            return Value('local', f'local {self.local_name(slot)}', line.index)

        m = _LD_ARG_N.match(line.mnemonic or '')
        if m or (line.mnemonic in ('ldarg', 'ldarg.s') and op):
            n = int(m.group(1)) if m else self._slot_of(op)
            return Value('arg', 'this' if n == 0 else f'argument {n}', line.index)

        m = _LDC_I4_N.match(line.mnemonic or '')
        if m:
            raw = m.group(1)
            v = -1 if raw.lower() == 'm1' else int(raw)
            return Value('const', str(v), line.index, v)

        if line.mnemonic == 'ldstr' and op:
            text = _unquote(op.text)
            return Value('string', f'"{text}"', line.index, text)

        if (line.mnemonic or '').startswith('ldc.') and op:
            return Value('const', op.text, line.index, op.value)

        if line.mnemonic == 'ldnull':
            return Value('const', 'null', line.index, None)

        if (line.mnemonic or '').startswith(('ldsfld', 'ldfld')) and op:
            return Value('field', f'field {op.text.rsplit("::", 1)[-1]}', line.index)

        return Value('result', 'a value', line.index)

    @staticmethod
    def _slot_of(op) -> int:
        m = re.search(r'\d+', op.text or '')
        return int(m.group()) if m else 0

    # -- calls -----------------------------------------------------------
    def _explain_call(self, line, entry, sig) -> dict:
        op = line.operands[0] if line.operands else None
        opcode = line.mnemonic

        if sig is None:
            # calli, or a signature we could not parse.
            if opcode == 'calli':
                self._pop(1)
                self._push(Value('result', 'a value', line.index))
                return {'title': 'Call through a function pointer taken from the stack',
                        'notes': ['The target is only known at run time, so static '
                                  'analysis cannot name it.']}
            target = op.text if op else 'an unknown method'
            return {'title': f'Call {target}', 'notes': []}

        taken = self._pop(sig.arg_count)
        receiver = None
        args = taken
        if sig.instance and taken:
            receiver, args = taken[0], taken[1:]

        notes = []
        owner = sig.type_name.rsplit('.', 1)[-1] if sig.type_name else ''

        if opcode == 'newobj':
            shown = ', '.join(self.describe(a) for a in args) if args else ''
            title = f'Create a new {owner}' + (f' from {shown}' if shown else '')
            self._push(Value('object', f'a {owner}', line.index))
            notes.append(f'Allocates {sig.type_name} and runs its constructor.')
            return {'title': title, 'notes': notes, 'signature': sig}

        if opcode in ('ldftn', 'ldvirtftn'):
            self._push(Value('result', f'a pointer to {sig.short}', line.index))
            return {'title': f'Push a function pointer to {sig.short}',
                    'notes': ['Usually a delegate being built.'], 'signature': sig}

        shown = ', '.join(self.describe(a) for a in args) if args else ''
        if sig.instance and receiver is not None:
            title = f'Call {sig.short} on {self.describe(receiver)}'
            if shown:
                title += f', passing {shown}'
        else:
            title = f'Call {sig.short}({shown})'

        if sig.returns_value:
            self._push(Value('result', f'the result of {sig.short}', line.index))
            notes.append(f'Returns {sig.returns}, which stays on the stack.')
        else:
            notes.append('Returns void, so nothing is left on the stack.')

        if opcode == 'callvirt':
            notes.append('Virtual dispatch: resolved against the object’s real type, '
                         'and throws NullReferenceException if it is null.')
        elif opcode == 'call' and sig.instance:
            notes.append('A non-virtual instance call — the exact method is fixed at '
                         'compile time, with no null check.')

        if sig.assembly:
            notes.append(f'Defined in [{sig.assembly}] {sig.type_name}.')
        return {'title': title, 'notes': notes, 'signature': sig}

    # -- main entry --------------------------------------------------------
    def explain(self, line) -> dict:
        out = {
            'index': line.index, 'raw': line.raw, 'kind': line.kind,
            'mnemonic': line.mnemonic, 'category': 'other', 'title': '',
            'detail': '', 'notes': [], 'flags': '', 'label': line.label,
            'comment': line.comment, 'address': line.address,
            'operands': [{'text': o.text, 'kind': o.kind} for o in line.operands],
            'stack_before': len(self.stack),
        }

        if line.kind == 'blank':
            return out
        if line.kind == 'comment':
            out['category'] = 'comment'
            out['title'] = 'Author’s comment'
            out['detail'] = line.comment or ''
            return out
        if line.kind == 'directive':
            out['category'] = 'directive'
            out['title'] = self._directive_title(line)
            out['detail'] = 'Metadata and structure, not executable code.'
            if line.mnemonic == '.method':
                self.stack = []
                self.local_values = {}
            return out
        if line.kind == 'label':
            out['category'] = 'label'
            out['title'] = f'Offset {line.label} — a branch target'
            return out

        entry = isa.lookup(line.mnemonic)
        out['category'] = entry['category'] if entry else 'other'
        op = line.operands[0] if line.operands else None
        sig = isa.parse_signature(op.text) if (op and op.kind == 'method') else None

        if entry and entry['category'] == 'call':
            result = self._explain_call(line, entry, sig)
            out['title'] = result['title']
            out['notes'].extend(result['notes'])
            if result.get('signature'):
                out['call'] = {
                    'target': result['signature'].full_name,
                    'short': result['signature'].short,
                    'assembly': result['signature'].assembly,
                    'returns': result['signature'].returns,
                    'params': list(result['signature'].params),
                    'instance': result['signature'].instance,
                    'opcode': line.mnemonic,
                }
        else:
            out['title'] = self._explain_simple(line, entry)

        if entry:
            out['detail'] = entry['detail'] or entry['summary']

        out['stack_after'] = len(self.stack)
        if self.verbosity == 'verbose' and self.stack:
            top = ', '.join(self.describe(v) for v in self.stack[-3:])
            out['notes'].append(f'Stack after this line ({len(self.stack)} deep): {top}')
        if line.comment:
            out['notes'].append(f'Source comment: {line.comment}')
        return out

    def _explain_simple(self, line, entry) -> str:
        opcode = line.mnemonic or ''
        op = line.operands[0] if line.operands else None

        # stloc: name what is being stored, and remember it.
        m = _ST_LOC_N.match(opcode)
        if m or (opcode in ('stloc', 'stloc.s') and op):
            slot = int(m.group(1)) if m else self._slot_of(op)
            value = self._pop(1)[0]
            self.local_values[slot] = value
            self.local_writes.setdefault(slot, []).append(line.index)
            return f'Store {self.describe(value)} into local {self.local_name(slot)}'

        if entry is None:
            self._push(UNKNOWN)
            return f'`{opcode}` is not in the CIL opcode table'

        pop, push = entry['pop'], entry['push']

        if opcode == 'ret':
            if self.stack:
                value = self._pop(1)[0]
                return f'Return {self.describe(value)} to the caller'
            return 'Return to the caller'

        if opcode == 'dup':
            top = self.stack[-1] if self.stack else UNKNOWN
            self._push(top)
            return f'Duplicate {self.describe(top)} on the stack'

        if opcode == 'pop':
            value = self._pop(1)[0]
            return f'Discard {self.describe(value)}'

        if opcode in ('box', 'unbox', 'unbox.any', 'castclass', 'isinst'):
            value = self._pop(1)[0]
            type_name = (op.text.rsplit('.', 1)[-1] if op else 'the type')
            self._push(Value('object', f'a {type_name}', line.index))
            verbs = {'box': 'Box', 'unbox': 'Unbox', 'unbox.any': 'Unbox',
                     'castclass': 'Cast', 'isinst': 'Test'}
            if opcode == 'isinst':
                return f'Test whether {self.describe(value)} is a {type_name}, pushing null if not'
            return f'{verbs[opcode]} {self.describe(value)} as {type_name}'

        if entry['category'] == 'control' and op is not None and op.kind == 'label':
            popped = self._pop(max(0, pop))
            target = op.text
            if opcode.startswith('brtrue'):
                return f'Jump to {target} if {self.describe(popped[0])} is non-zero or non-null'
            if opcode.startswith('brfalse'):
                return f'Jump to {target} if {self.describe(popped[0])} is zero or null'
            if opcode.startswith('br'):
                return f'Jump to {target} — always taken'
            if popped and len(popped) == 2:
                rel = {'beq': 'equals', 'bne.un': 'differs from', 'bge': 'is at least',
                       'bgt': 'is greater than', 'ble': 'is at most',
                       'blt': 'is less than'}.get(opcode.rstrip('.s').replace('.un', ''), 'compares to')
                return (f'Jump to {target} if {self.describe(popped[0])} '
                        f'{rel} {self.describe(popped[1])}')
            return f'Jump to {target}'

        m = _LD_LOC_N.match(opcode)
        if m or (opcode in ('ldloc', 'ldloc.s') and op):
            slot = int(m.group(1)) if m else self._slot_of(op)
            value = self._value_for_push(line, entry)
            self._push(value)
            self.local_reads.setdefault(slot, []).append(line.index)
            known = self.local_values.get(slot)
            suffix = ''
            if known is not None and known.kind in ('string', 'const'):
                suffix = f', currently {self.describe(known)}'
            return f'Push local {self.local_name(slot)}{suffix}'

        # Default: apply the recorded stack effect and fill the template.
        popped = self._pop(max(0, pop))
        for _ in range(max(0, push)):
            self._push(self._value_for_push(line, entry))

        template = entry['template'] or entry['summary']
        if '{op}' in template:
            return template.replace('{op}', op.text if op else 'the operand')
        return template

    def _directive_title(self, line) -> str:
        mnemonic = (line.mnemonic or '').lower()
        if mnemonic == '.method':
            return f'Method definition{f": {line.label}" if line.label else ""}'
        if mnemonic == '.maxstack':
            return 'Declares how deep the evaluation stack gets in this method'
        if mnemonic == '.locals':
            return 'Declares the method’s local variable slots'
        if mnemonic == '.entrypoint':
            return 'Marks this method as the assembly’s entry point'
        if mnemonic == '.try':
            return 'Start of a protected (try) region'
        if mnemonic in ('catch', 'finally', 'filter', 'fault'):
            return f'Start of a {mnemonic} handler'
        return 'Assembler directive'
