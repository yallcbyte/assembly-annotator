"""Turn a ParsedLine into plain English.

Two things lift this above a mnemonic lookup table:

1. Operand awareness -- `mov ecx, 5` reads "Set ECX (counter) to 5", not
   the generic "copy data from source to destination".
2. A running register model -- constants are propagated forward, so by the
   time we reach `int 0x80` we know EAX held 4 and can say "write()".
"""

import re
from typing import Dict, List, Optional

from . import isa, registers, syscalls
from .parser import ParsedLine

DIRECTIVE_HELP = {
    'section': 'Start a new section of the object file',
    'segment': 'Start a new segment of the object file',
    'global': 'Export this symbol so the linker can see it',
    'globl': 'Export this symbol so the linker can see it',
    'extern': 'Declare a symbol that lives in another object file',
    'bits': 'Tell the assembler which CPU mode to assemble for',
    'org': 'Set the assembly origin address',
    'align': 'Pad until the next aligned address',
    'db': 'Reserve and initialise bytes of data',
    'dw': 'Reserve and initialise 16-bit words of data',
    'dd': 'Reserve and initialise 32-bit doublewords of data',
    'dq': 'Reserve and initialise 64-bit quadwords of data',
    'resb': 'Reserve uninitialised bytes',
    'resw': 'Reserve uninitialised words',
    'resd': 'Reserve uninitialised doublewords',
    'equ': 'Define a named constant',
    'times': 'Repeat the following directive or instruction',
    'include': 'Pull in another source file',
}


def decode_ascii(value: int) -> Optional[str]:
    """Little-endian bytes of an immediate, if they are all printable ASCII."""
    if value is None or value <= 0xFF:
        return None
    chars = []
    v = value
    while v:
        b = v & 0xFF
        if not (0x20 <= b <= 0x7E):
            return None
        chars.append(chr(b))
        v >>= 8
    return ''.join(chars) if len(chars) >= 2 else None


def render_operand(op, arch: str) -> str:
    """One operand as a readable phrase."""
    if op.kind == 'register':
        return registers.describe(op.text, arch)
    if op.kind == 'immediate':
        if op.value is not None and re.search(r'0x|h$', op.text, re.I):
            return f'{op.text} ({op.value})'
        return op.text.lstrip('$#')
    if op.kind == 'memory':
        return f'the memory at {op.text}'
    return op.text


def short_operand(op, arch: str) -> str:
    """Compact form, used where the long form would bloat the sentence."""
    if op.kind == 'register':
        return registers.normalise(op.text).upper()
    if op.kind == 'memory':
        return f'[{op.text.strip("[]")}]' if '[' not in op.text else op.text
    return op.text.lstrip('$#')


class Explainer:
    """Walks a listing in order, keeping a light model of register state."""

    def __init__(self, arch: str = 'x86', syntax: str = 'intel', verbosity: str = 'normal'):
        self.arch = arch
        self.syntax = syntax
        self.verbosity = verbosity
        self.reg_values: Dict[str, Optional[int]] = {}
        self.stack_depth = 0
        self.bits = 32

    # -- register model ----------------------------------------------
    def _parent(self, token: str) -> Optional[str]:
        info = registers.lookup(token, self.arch)
        return info[2] if info else None

    def _set_reg(self, token: str, value: Optional[int]):
        parent = self._parent(token)
        if parent:
            self.reg_values[parent] = value

    def _get_reg(self, token: str) -> Optional[int]:
        parent = self._parent(token)
        return self.reg_values.get(parent) if parent else None

    def _track(self, line: ParsedLine):
        """Update the register model after explaining a line."""
        m, ops = line.mnemonic, line.operands
        if not m or not ops:
            return
        if registers.width_of(ops[0].text, self.arch) == 64:
            self.bits = 64
        if m in ('mov', 'movl', 'movq', 'movabs', 'li', 'movz') and len(ops) == 2:
            if ops[1].kind == 'immediate':
                self._set_reg(ops[0].text, ops[1].value)
            elif ops[1].kind == 'register':
                self._set_reg(ops[0].text, self._get_reg(ops[1].text))
            else:
                self._set_reg(ops[0].text, None)
        elif m in ('xor', 'sub', 'eor') and len(ops) == 2 and \
                ops[0].kind == ops[1].kind == 'register' and \
                registers.normalise(ops[0].text) == registers.normalise(ops[1].text):
            self._set_reg(ops[0].text, 0)
        elif m in ('add', 'sub', 'inc', 'dec') and ops[0].kind == 'register':
            cur = self._get_reg(ops[0].text)
            delta = None
            if m == 'inc':
                delta = 1
            elif m == 'dec':
                delta = -1
            elif len(ops) == 2 and ops[1].kind == 'immediate' and ops[1].value is not None:
                delta = ops[1].value if m == 'add' else -ops[1].value
            self._set_reg(ops[0].text, (cur + delta) if (cur is not None and delta is not None) else None)
        elif m == 'pop' and ops[0].kind == 'register':
            self._set_reg(ops[0].text, None)
            self.stack_depth = max(0, self.stack_depth - 1)
        elif m == 'push':
            self.stack_depth += 1
        elif m == 'call':
            # Calls clobber the caller-saved registers.
            for r in ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'):
                self.reg_values.pop(r, None)
        elif ops[0].kind == 'register':
            self._set_reg(ops[0].text, None)

    # -- idioms --------------------------------------------------------
    def _idiom(self, line: ParsedLine) -> Optional[dict]:
        """Recognise multi-token idioms that deserve their own sentence."""
        m, ops = line.mnemonic, line.operands
        n = len(ops)
        same = (n == 2 and ops[0].kind == 'register' and ops[1].kind == 'register'
                and registers.normalise(ops[0].text) == registers.normalise(ops[1].text))
        reg0 = short_operand(ops[0], self.arch) if n else ''

        if m in ('xor', 'eor') and same:
            return {'title': f'Zero out {reg0}',
                    'note': 'The standard two-byte way to set a register to 0 — '
                            'shorter than `mov` and it clears the flags as a side effect.'}
        if m == 'sub' and same:
            return {'title': f'Zero out {reg0}',
                    'note': 'Same effect as `xor reg, reg`: subtracting a value from itself leaves 0.'}
        if m == 'test' and same:
            return {'title': f'Check whether {reg0} is zero',
                    'note': 'Cheaper than `cmp reg, 0`. The conditional jump that follows '
                            'usually branches on the null/zero case.'}
        if m == 'or' and same:
            return {'title': f'Check whether {reg0} is zero (and leave it unchanged)',
                    'note': 'OR-ing a register with itself only sets flags — another zero test.'}
        if m == 'mov' and n == 2 and ops[0].kind == ops[1].kind == 'register':
            a, b = registers.normalise(ops[0].text), registers.normalise(ops[1].text)
            if (a, b) in (('ebp', 'esp'), ('rbp', 'rsp')):
                return {'title': 'Anchor the frame pointer to the current stack top',
                        'note': 'Second half of the function prologue. From here on, locals are '
                                'addressed as [EBP-n] and arguments as [EBP+n].'}
            if (a, b) in (('esp', 'ebp'), ('rsp', 'rbp')):
                return {'title': 'Discard the local stack frame',
                        'note': 'First half of the epilogue — throws away every local variable at once.'}
        if m == 'sub' and n == 2 and ops[0].kind == 'register' and ops[1].kind == 'immediate' \
                and registers.normalise(ops[0].text) in ('esp', 'rsp') and ops[1].value:
            return {'title': f'Reserve {ops[1].value} bytes of local stack space',
                    'note': f'Space for this function’s local variables ({ops[1].value} bytes).'}
        if m == 'add' and n == 2 and ops[0].kind == 'register' and ops[1].kind == 'immediate' \
                and registers.normalise(ops[0].text) in ('esp', 'rsp') and ops[1].value:
            words = ops[1].value // 4
            return {'title': f'Release {ops[1].value} bytes of stack space',
                    'note': f'Typical cdecl cleanup after a call — roughly {words} pushed argument(s).'}
        if m in ('shl', 'sal') and n == 2 and ops[1].kind == 'immediate' and ops[1].value is not None:
            return {'title': f'Multiply {reg0} by {2 ** ops[1].value}',
                    'note': f'A left shift by {ops[1].value} is a power-of-two multiply the compiler '
                            'chose over an actual MUL.'}
        if m == 'shr' and n == 2 and ops[1].kind == 'immediate' and ops[1].value is not None:
            return {'title': f'Divide {reg0} by {2 ** ops[1].value}, unsigned',
                    'note': f'A right shift by {ops[1].value} is a power-of-two divide.'}
        if m == 'lea' and n == 2 and ops[1].kind == 'memory':
            inner = ops[1].text.strip('[]')
            if re.search(r'[+\-*]', inner):
                return {'title': f'Compute {inner} and store it in {reg0}',
                        'note': 'LEA used as arithmetic: it evaluates the address expression '
                                'without touching memory and without disturbing the flags.'}
        if m == 'and' and n == 2 and ops[1].kind == 'immediate' and ops[1].value is not None:
            v = ops[1].value
            if v in (0xFF, 0xFFFF, 0xFFFFFFFF):
                keep = {0xFF: 'lowest byte', 0xFFFF: 'low 16 bits', 0xFFFFFFFF: 'low 32 bits'}[v]
                return {'title': f'Keep only the {keep} of {reg0}',
                        'note': 'A masking operation — the bits above the mask are cleared.'}
            if v and (v + 1) & v == 0:
                return {'title': f'Reduce {reg0} modulo {v + 1}',
                        'note': f'AND with {hex(v)} is the cheap way to compute "mod {v + 1}".'}
            if v < 0 or (v & (v - 1)) == 0 and v > 1:
                return {'title': f'Isolate bit {v.bit_length() - 1} of {reg0}',
                        'note': 'Single-bit mask — a flag test.'}
        if m == 'push' and n == 1 and ops[0].kind == 'register' and \
                registers.normalise(ops[0].text) in ('ebp', 'rbp'):
            return {'title': 'Save the caller’s frame pointer',
                    'note': 'First half of the function prologue.'}
        if m == 'nop':
            return {'title': 'Do nothing for one instruction',
                    'note': 'Padding, alignment, or a patched-out instruction.'}
        return None

    # -- syscalls ------------------------------------------------------
    def _syscall_note(self, line: ParsedLine) -> Optional[dict]:
        m, ops = line.mnemonic, line.operands
        sel_reg, bits = None, self.bits
        if m == 'int' and ops and ops[0].kind == 'immediate' and ops[0].value == 0x80:
            sel_reg, bits = 'rax', 32
        elif m == 'syscall':
            sel_reg, bits = 'rax', 64
        elif m == 'svc' and self.arch == 'arm':
            sel_reg, bits = 'x8', 64
        if not sel_reg:
            return None

        num = self.reg_values.get(sel_reg)
        if num is None:
            reg_name = {'rax': 'EAX/RAX', 'x8': 'X8'}[sel_reg]
            return {'title': 'Enter the kernel to run a system call',
                    'note': f'The call number comes from {reg_name}, which this listing does not '
                            'set to a constant we can follow.'}
        entry = syscalls.lookup(num, self.arch, bits)
        if not entry:
            return {'title': f'Enter the kernel for system call #{num}',
                    'note': f'System call number {num} is not in the bundled table.'}
        name, desc = entry
        note = f'System call {num} on this ABI is {name}() — {desc}.'
        if name in syscalls.NOTEWORTHY:
            note += f' Worth a look: {syscalls.NOTEWORTHY[name]}.'
        return {'title': f'Invoke the {name}() system call — {desc}',
                'note': note, 'syscall': name}

    # -- main entry point ----------------------------------------------
    def explain(self, line: ParsedLine) -> dict:
        out = {
            'index': line.index,
            'raw': line.raw,
            'kind': line.kind,
            'mnemonic': line.mnemonic,
            'category': 'other',
            'title': '',
            'detail': '',
            'notes': [],
            'flags': '',
            'label': line.label,
            'comment': line.comment,
            'address': line.address,
            'operands': [{'text': o.text, 'kind': o.kind} for o in line.operands],
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
            base = (line.mnemonic or '').lstrip('.')
            out['title'] = DIRECTIVE_HELP.get(base, 'Assembler directive — instructs the '
                                                    'assembler rather than the CPU')
            if line.operands:
                out['title'] += f" ({', '.join(o.text for o in line.operands)})"
            out['detail'] = 'Directives shape the output file. They produce no machine code of their own.'
            return out
        if line.kind == 'label' and not line.mnemonic:
            out['category'] = 'label'
            out['title'] = f'Label “{line.label}” — a named position jumps can target'
            out['detail'] = 'Labels carry no machine code; they name an address for branches and calls.'
            return out

        entry = isa.lookup(line.mnemonic, self.arch)
        out['category'] = entry['category'] if entry else 'other'
        out['flags'] = entry['flags'] if entry else ''

        syscall = self._syscall_note(line)
        idiom = self._idiom(line)

        if syscall:
            out['title'] = syscall['title']
            out['notes'].append(syscall['note'])
            if 'syscall' in syscall:
                out['syscall'] = syscall['syscall']
        elif idiom:
            out['title'] = idiom['title']
            out['notes'].append(idiom['note'])
        elif entry and entry['template']:
            out['title'] = self._fill(entry['template'], line)
        elif entry:
            out['title'] = entry['summary']
        else:
            out['title'] = f'`{line.mnemonic}` is not in the instruction database'
            out['notes'].append('Unrecognised mnemonic. It may belong to another architecture, '
                                'be a macro, or be a rarely used extension.')

        if entry and entry['detail'] and self.verbosity != 'brief':
            out['detail'] = entry['detail']
        elif entry:
            out['detail'] = entry['summary']

        if line.prefix:
            pref = isa.lookup(line.prefix, self.arch)
            out['notes'].insert(0, f'`{line.prefix}` prefix: '
                                   f'{pref["summary"] if pref else "modifies the instruction"}.')

        # Surface what we know about the operand registers.
        if self.verbosity == 'verbose':
            for op in line.operands:
                if op.kind == 'register':
                    known = self._get_reg(op.text)
                    if known is not None:
                        out['notes'].append(
                            f'{registers.normalise(op.text).upper()} holds {known} '
                            f'({hex(known)}) at this point.')

        if entry and entry['flags'] and self.verbosity == 'verbose':
            out['notes'].append(f'Writes flags: {entry["flags"]}.')
        # Packed immediates are often ASCII smuggled into the instruction stream.
        for op in line.operands:
            if op.kind == 'immediate' and op.value is not None:
                text = decode_ascii(op.value)
                if text:
                    out['notes'].append(
                        f'{op.text} is the ASCII text \u201c{text}\u201d laid out little-endian '
                        f'\u2014 a string being built inside the code.')
                    out['ascii'] = text

        if line.comment:
            out['notes'].append(f'Source comment: {line.comment}')

        self._track(line)
        return out

    def _fill(self, template: str, line: ParsedLine) -> str:
        ops = line.operands
        mapping = {}
        for i, op in enumerate(ops):
            mapping[f'op{i}'] = render_operand(op, self.arch)
        if ops:
            mapping['dst'] = render_operand(ops[0], self.arch)
        if len(ops) > 1:
            mapping['src'] = render_operand(ops[1], self.arch)
            # `shl eax, 3` wants the bare count inside "2^{src}", not the long form.
            if ops[1].kind == 'immediate':
                mapping['src'] = ops[1].text.lstrip('$#')
        for i in range(len(ops), 4):
            mapping.setdefault(f'op{i}', 'the operand')
        mapping.setdefault('dst', 'the destination')
        mapping.setdefault('src', 'the source')
        try:
            return template.format(**mapping)
        except (KeyError, IndexError):
            return template
