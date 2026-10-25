"""Stack frame reconstruction.

Reading `[ebp-0x14]` tells you nothing on its own. This module works out what
each slot is for -- argument, local, saved frame pointer, return address --
and which lines touch it, so the layout can be drawn as a diagram.
"""

import re
from typing import List, Optional

from . import registers

# `dword ptr [ebp - 0x14]`, `[rbp+16]`, `-0x4(%rbp)`, `[esp+8]`
_INTEL_RE = re.compile(
    # MASM/Intel writes `dword ptr [..]`; NASM writes `dword [..]`.
    r'(?:(?P<size>byte|word|dword|qword|tbyte|xmmword)\s+(?:ptr\s*)?)?'
    r'\[\s*%?(?P<reg>[a-z]{2,3})\s*(?P<sign>[+-])?\s*(?P<off>0x[0-9a-fA-F]+|\d+)?\s*\]',
    re.IGNORECASE)
_ATT_RE = re.compile(
    r'(?P<sign>-)?(?P<off>0x[0-9a-fA-F]+|\d+)?\(\s*%(?P<reg>[a-z]{2,3})\s*\)',
    re.IGNORECASE)

_SIZE_BYTES = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8, 'tbyte': 10, 'xmmword': 16}

FRAME_REGS = {'ebp', 'rbp', 'bp'}
STACK_REGS = {'esp', 'rsp', 'sp'}

WRITERS = {'mov', 'add', 'sub', 'and', 'or', 'xor', 'inc', 'dec', 'neg', 'not',
           'shl', 'shr', 'sar', 'sal', 'stos', 'stosb', 'stosd', 'pop'}


def _parse_memory(text: str):
    """Return (register, signed offset, size in bytes) for a memory operand."""
    m = _INTEL_RE.search(text)
    if m:
        reg = registers.normalise(m.group('reg'))
        off = int(m.group('off'), 0) if m.group('off') else 0
        if m.group('sign') == '-':
            off = -off
        size = _SIZE_BYTES.get((m.group('size') or '').lower())
        return reg, off, size
    m = _ATT_RE.search(text)
    if m:
        reg = registers.normalise(m.group('reg'))
        off = int(m.group('off'), 0) if m.group('off') else 0
        if m.group('sign') == '-':
            off = -off
        return reg, off, None
    return None, None, None


def analyse_frame(lines, arch: str = 'x86') -> dict:
    """Describe the stack frame this listing builds, if it builds one."""
    instructions = [l for l in lines if l.kind == 'instruction']
    word = 8 if any(registers.width_of(o.text, arch) == 64
                    for l in instructions for o in l.operands) else 4

    prologue = _find_prologue(instructions)
    reserved = prologue['reserved']

    slots = {}
    for line in instructions:
        for position, op in enumerate(line.operands):
            if op.kind != 'memory':
                continue
            reg, off, size = _parse_memory(op.text)
            if reg is None:
                continue
            if reg in FRAME_REGS:
                base = 'frame'
            elif reg in STACK_REGS:
                base = 'stack'
            else:
                continue
            key = (base, off)
            slot = slots.setdefault(key, {
                'base': base, 'offset': off, 'size': size or word,
                'reads': [], 'writes': [],
            })
            if size and size > slot['size']:
                slot['size'] = size
            writing = position == 0 and line.mnemonic in WRITERS
            (slot['writes'] if writing else slot['reads']).append(line.index)

    layout = []
    for (base, off), slot in slots.items():
        layout.append({**slot, **_describe_slot(base, off, word, reserved)})

    # Saved frame pointer and return address are implied by the prologue.
    if prologue['has_frame']:
        layout.append({'base': 'frame', 'offset': 0, 'size': word,
                       'name': 'saved frame pointer', 'role': 'saved',
                       'detail': 'The caller’s EBP/RBP, restored on the way out.',
                       'reads': [], 'writes': [], 'implied': True})
        layout.append({'base': 'frame', 'offset': word, 'size': word,
                       'name': 'return address', 'role': 'return',
                       'detail': 'Pushed by CALL. Overwriting this is how a stack '
                                 'buffer overflow takes control.',
                       'reads': [], 'writes': [], 'implied': True})

    layout.sort(key=lambda s: (s['base'] != 'frame', -s['offset']))

    return {
        'has_frame': prologue['has_frame'],
        'word': word,
        'reserved': reserved,
        'prologue_lines': prologue['lines'],
        'epilogue_lines': _find_epilogue(instructions),
        'slots': layout,
        'arguments': [s for s in layout if s['role'] == 'argument'],
        'locals': [s for s in layout if s['role'] == 'local'],
        'max_depth': max([abs(s['offset']) for s in layout if s['offset'] < 0] + [reserved, 0]),
    }


def _describe_slot(base: str, off: int, word: int, reserved: int) -> dict:
    if base == 'stack':
        return {'name': f'[esp+{off}]' if off >= 0 else f'[esp{off}]',
                'role': 'outgoing' if off >= 0 else 'scratch',
                'detail': 'Addressed from the stack pointer — usually an outgoing '
                          'call argument or scratch space.'}
    if off > word:
        # [ebp+0] saved frame pointer, [ebp+word] return address,
        # so the first argument sits at [ebp + 2*word].
        n = off // word - 1
        return {'name': f'argument {n}', 'role': 'argument',
                'detail': f'Caller-supplied argument at [EBP+{off}]. Arguments sit '
                          'above the saved frame pointer and return address.'}
    if off == word:
        return {'name': 'return address', 'role': 'return',
                'detail': 'Pushed by CALL.'}
    if off == 0:
        return {'name': 'saved frame pointer', 'role': 'saved',
                'detail': 'The caller’s frame pointer.'}
    return {'name': f'local at {off}', 'role': 'local',
            'detail': f'A local variable {abs(off)} bytes below the frame pointer'
                      + (f', inside the {reserved} bytes reserved by the prologue.'
                         if reserved and abs(off) <= reserved else '.')}


def _find_prologue(instructions) -> dict:
    """Detect push ebp / mov ebp, esp / sub esp, N at the top of a function."""
    found, reserved, has_frame = [], 0, False
    for line in instructions[:8]:
        m, ops = line.mnemonic, line.operands
        if m == 'push' and ops and registers.normalise(ops[0].text) in FRAME_REGS:
            found.append(line.index)
        elif (m == 'mov' and len(ops) == 2
              and registers.normalise(ops[0].text) in FRAME_REGS
              and registers.normalise(ops[1].text) in STACK_REGS):
            found.append(line.index)
            has_frame = True
        elif (m == 'sub' and len(ops) == 2
              and registers.normalise(ops[0].text) in STACK_REGS
              and ops[1].kind == 'immediate' and ops[1].value):
            found.append(line.index)
            reserved = ops[1].value
        elif m == 'enter' and ops and ops[0].kind == 'immediate' and ops[0].value:
            found.append(line.index)
            reserved, has_frame = ops[0].value, True
    return {'lines': found, 'reserved': reserved, 'has_frame': has_frame}


def _find_epilogue(instructions) -> List[int]:
    found = []
    for line in instructions[-6:]:
        m, ops = line.mnemonic, line.operands
        if m == 'leave':
            found.append(line.index)
        elif m == 'pop' and ops and registers.normalise(ops[0].text) in FRAME_REGS:
            found.append(line.index)
        elif (m == 'mov' and len(ops) == 2
              and registers.normalise(ops[0].text) in STACK_REGS
              and registers.normalise(ops[1].text) in FRAME_REGS):
            found.append(line.index)
        elif m in ('ret', 'retn'):
            found.append(line.index)
    return found
