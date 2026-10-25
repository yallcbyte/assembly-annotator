"""Decode raw CIL bytecode into ildasm-style text.

The decoder knows nothing about metadata. Tokens are handed to a resolver
object, which keeps this module testable with hand-built byte strings and a
dictionary standing in for a real assembly.

Operand kinds follow ECMA-335 Partition III.
"""

import struct
from typing import List, NamedTuple, Optional

# operand kinds
NONE, I1, I4, I8, R4, R8 = 'none', 'i1', 'i4', 'i8', 'r4', 'r8'
VAR8, VAR16 = 'var8', 'var16'
BR8, BR32, SWITCH = 'br8', 'br32', 'switch'
METHOD, FIELD, TYPE, TOKEN, STRING, SIG = 'method', 'field', 'type', 'tok', 'string', 'sig'

_SIZES = {NONE: 0, I1: 1, I4: 4, I8: 8, R4: 4, R8: 8, VAR8: 1, VAR16: 2,
          BR8: 1, BR32: 4, METHOD: 4, FIELD: 4, TYPE: 4, TOKEN: 4, STRING: 4, SIG: 4}

ONE_BYTE = {
    0x00: ('nop', NONE), 0x01: ('break', NONE),
    0x02: ('ldarg.0', NONE), 0x03: ('ldarg.1', NONE), 0x04: ('ldarg.2', NONE), 0x05: ('ldarg.3', NONE),
    0x06: ('ldloc.0', NONE), 0x07: ('ldloc.1', NONE), 0x08: ('ldloc.2', NONE), 0x09: ('ldloc.3', NONE),
    0x0A: ('stloc.0', NONE), 0x0B: ('stloc.1', NONE), 0x0C: ('stloc.2', NONE), 0x0D: ('stloc.3', NONE),
    0x0E: ('ldarg.s', VAR8), 0x0F: ('ldarga.s', VAR8), 0x10: ('starg.s', VAR8),
    0x11: ('ldloc.s', VAR8), 0x12: ('ldloca.s', VAR8), 0x13: ('stloc.s', VAR8),
    0x14: ('ldnull', NONE), 0x15: ('ldc.i4.m1', NONE),
    0x16: ('ldc.i4.0', NONE), 0x17: ('ldc.i4.1', NONE), 0x18: ('ldc.i4.2', NONE),
    0x19: ('ldc.i4.3', NONE), 0x1A: ('ldc.i4.4', NONE), 0x1B: ('ldc.i4.5', NONE),
    0x1C: ('ldc.i4.6', NONE), 0x1D: ('ldc.i4.7', NONE), 0x1E: ('ldc.i4.8', NONE),
    0x1F: ('ldc.i4.s', I1), 0x20: ('ldc.i4', I4), 0x21: ('ldc.i8', I8),
    0x22: ('ldc.r4', R4), 0x23: ('ldc.r8', R8),
    0x25: ('dup', NONE), 0x26: ('pop', NONE),
    0x27: ('jmp', METHOD), 0x28: ('call', METHOD), 0x29: ('calli', SIG), 0x2A: ('ret', NONE),
    0x2B: ('br.s', BR8), 0x2C: ('brfalse.s', BR8), 0x2D: ('brtrue.s', BR8),
    0x2E: ('beq.s', BR8), 0x2F: ('bge.s', BR8), 0x30: ('bgt.s', BR8), 0x31: ('ble.s', BR8),
    0x32: ('blt.s', BR8), 0x33: ('bne.un.s', BR8), 0x34: ('bge.un.s', BR8),
    0x35: ('bgt.un.s', BR8), 0x36: ('ble.un.s', BR8), 0x37: ('blt.un.s', BR8),
    0x38: ('br', BR32), 0x39: ('brfalse', BR32), 0x3A: ('brtrue', BR32),
    0x3B: ('beq', BR32), 0x3C: ('bge', BR32), 0x3D: ('bgt', BR32), 0x3E: ('ble', BR32),
    0x3F: ('blt', BR32), 0x40: ('bne.un', BR32), 0x41: ('bge.un', BR32),
    0x42: ('bgt.un', BR32), 0x43: ('ble.un', BR32), 0x44: ('blt.un', BR32),
    0x45: ('switch', SWITCH),
    0x46: ('ldind.i1', NONE), 0x47: ('ldind.u1', NONE), 0x48: ('ldind.i2', NONE),
    0x49: ('ldind.u2', NONE), 0x4A: ('ldind.i4', NONE), 0x4B: ('ldind.u4', NONE),
    0x4C: ('ldind.i8', NONE), 0x4D: ('ldind.i', NONE), 0x4E: ('ldind.r4', NONE),
    0x4F: ('ldind.r8', NONE), 0x50: ('ldind.ref', NONE),
    0x51: ('stind.ref', NONE), 0x52: ('stind.i1', NONE), 0x53: ('stind.i2', NONE),
    0x54: ('stind.i4', NONE), 0x55: ('stind.i8', NONE), 0x56: ('stind.r4', NONE),
    0x57: ('stind.r8', NONE),
    0x58: ('add', NONE), 0x59: ('sub', NONE), 0x5A: ('mul', NONE), 0x5B: ('div', NONE),
    0x5C: ('div.un', NONE), 0x5D: ('rem', NONE), 0x5E: ('rem.un', NONE),
    0x5F: ('and', NONE), 0x60: ('or', NONE), 0x61: ('xor', NONE),
    0x62: ('shl', NONE), 0x63: ('shr', NONE), 0x64: ('shr.un', NONE),
    0x65: ('neg', NONE), 0x66: ('not', NONE),
    0x67: ('conv.i1', NONE), 0x68: ('conv.i2', NONE), 0x69: ('conv.i4', NONE),
    0x6A: ('conv.i8', NONE), 0x6B: ('conv.r4', NONE), 0x6C: ('conv.r8', NONE),
    0x6D: ('conv.u4', NONE), 0x6E: ('conv.u8', NONE),
    0x6F: ('callvirt', METHOD), 0x70: ('cpobj', TYPE), 0x71: ('ldobj', TYPE),
    0x72: ('ldstr', STRING), 0x73: ('newobj', METHOD), 0x74: ('castclass', TYPE),
    0x75: ('isinst', TYPE), 0x76: ('conv.r.un', NONE),
    0x79: ('unbox', TYPE), 0x7A: ('throw', NONE),
    0x7B: ('ldfld', FIELD), 0x7C: ('ldflda', FIELD), 0x7D: ('stfld', FIELD),
    0x7E: ('ldsfld', FIELD), 0x7F: ('ldsflda', FIELD), 0x80: ('stsfld', FIELD),
    0x81: ('stobj', TYPE),
    0x82: ('conv.ovf.i1.un', NONE), 0x83: ('conv.ovf.i2.un', NONE),
    0x84: ('conv.ovf.i4.un', NONE), 0x85: ('conv.ovf.i8.un', NONE),
    0x86: ('conv.ovf.u1.un', NONE), 0x87: ('conv.ovf.u2.un', NONE),
    0x88: ('conv.ovf.u4.un', NONE), 0x89: ('conv.ovf.u8.un', NONE),
    0x8A: ('conv.ovf.i.un', NONE), 0x8B: ('conv.ovf.u.un', NONE),
    0x8C: ('box', TYPE), 0x8D: ('newarr', TYPE), 0x8E: ('ldlen', NONE), 0x8F: ('ldelema', TYPE),
    0x90: ('ldelem.i1', NONE), 0x91: ('ldelem.u1', NONE), 0x92: ('ldelem.i2', NONE),
    0x93: ('ldelem.u2', NONE), 0x94: ('ldelem.i4', NONE), 0x95: ('ldelem.u4', NONE),
    0x96: ('ldelem.i8', NONE), 0x97: ('ldelem.i', NONE), 0x98: ('ldelem.r4', NONE),
    0x99: ('ldelem.r8', NONE), 0x9A: ('ldelem.ref', NONE),
    0x9B: ('stelem.i', NONE), 0x9C: ('stelem.i1', NONE), 0x9D: ('stelem.i2', NONE),
    0x9E: ('stelem.i4', NONE), 0x9F: ('stelem.i8', NONE), 0xA0: ('stelem.r4', NONE),
    0xA1: ('stelem.r8', NONE), 0xA2: ('stelem.ref', NONE),
    0xA3: ('ldelem', TYPE), 0xA4: ('stelem', TYPE), 0xA5: ('unbox.any', TYPE),
    0xB3: ('conv.ovf.i1', NONE), 0xB4: ('conv.ovf.u1', NONE), 0xB5: ('conv.ovf.i2', NONE),
    0xB6: ('conv.ovf.u2', NONE), 0xB7: ('conv.ovf.i4', NONE), 0xB8: ('conv.ovf.u4', NONE),
    0xB9: ('conv.ovf.i8', NONE), 0xBA: ('conv.ovf.u8', NONE),
    0xC2: ('refanyval', TYPE), 0xC3: ('ckfinite', NONE), 0xC6: ('mkrefany', TYPE),
    0xD0: ('ldtoken', TOKEN),
    0xD1: ('conv.u2', NONE), 0xD2: ('conv.u1', NONE), 0xD3: ('conv.i', NONE),
    0xD4: ('conv.ovf.i', NONE), 0xD5: ('conv.ovf.u', NONE),
    0xD6: ('add.ovf', NONE), 0xD7: ('add.ovf.un', NONE), 0xD8: ('mul.ovf', NONE),
    0xD9: ('mul.ovf.un', NONE), 0xDA: ('sub.ovf', NONE), 0xDB: ('sub.ovf.un', NONE),
    0xDC: ('endfinally', NONE), 0xDD: ('leave', BR32), 0xDE: ('leave.s', BR8),
    0xDF: ('stind.i', NONE), 0xE0: ('conv.u', NONE),
}

TWO_BYTE = {  # second byte after 0xFE
    0x00: ('arglist', NONE), 0x01: ('ceq', NONE), 0x02: ('cgt', NONE), 0x03: ('cgt.un', NONE),
    0x04: ('clt', NONE), 0x05: ('clt.un', NONE), 0x06: ('ldftn', METHOD),
    0x07: ('ldvirtftn', METHOD), 0x09: ('ldarg', VAR16), 0x0A: ('ldarga', VAR16),
    0x0B: ('starg', VAR16), 0x0C: ('ldloc', VAR16), 0x0D: ('ldloca', VAR16),
    0x0E: ('stloc', VAR16), 0x0F: ('localloc', NONE), 0x11: ('endfilter', NONE),
    0x12: ('unaligned.', I1), 0x13: ('volatile.', NONE), 0x14: ('tail.', NONE),
    0x15: ('initobj', TYPE), 0x16: ('constrained.', TYPE), 0x17: ('cpblk', NONE),
    0x18: ('initblk', NONE), 0x19: ('no.', I1), 0x1A: ('rethrow', NONE),
    0x1C: ('sizeof', TYPE), 0x1D: ('refanytype', NONE), 0x1E: ('readonly.', NONE),
}


class Instruction(NamedTuple):
    offset: int
    opcode: str
    kind: str
    operand: Optional[object]   # raw value: int, float, token, target offset(s)
    text: str                   # rendered operand, '' if none


class DecodeError(ValueError):
    pass


def label(offset: int) -> str:
    return f'IL_{offset:04x}'


def _escape(s: str) -> str:
    return (s.replace('\\', '\\\\').replace('"', '\\"')
             .replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t'))


def decode(code: bytes, resolver=None, max_instructions: int = 20000) -> List[Instruction]:
    """Decode a method body. Unknown opcodes stop decoding with a marker.

    `resolver` may provide method(tok), field(tok), type(tok), token(tok),
    string(tok) and signature(tok); any it lacks render as raw tokens.
    """
    out: List[Instruction] = []
    pos, n = 0, len(code)
    while pos < n and len(out) < max_instructions:
        start = pos
        b = code[pos]
        pos += 1
        if b == 0xFE:
            if pos >= n:
                raise DecodeError(f'truncated two-byte opcode at {label(start)}')
            entry = TWO_BYTE.get(code[pos])
            pos += 1
        else:
            entry = ONE_BYTE.get(b)
        if entry is None:
            raise DecodeError(f'unknown opcode 0x{b:02x} at {label(start)}')
        name, kind = entry

        if kind == SWITCH:
            if pos + 4 > n:
                raise DecodeError(f'truncated switch at {label(start)}')
            count = struct.unpack_from('<I', code, pos)[0]
            pos += 4
            if count > 4096 or pos + 4 * count > n:
                raise DecodeError(f'implausible switch table at {label(start)}')
            rel = struct.unpack_from(f'<{count}i', code, pos)
            pos += 4 * count
            targets = [pos + r for r in rel]
            out.append(Instruction(start, name, kind, targets,
                                   '(' + ', '.join(label(t) for t in targets) + ')'))
            continue

        size = _SIZES[kind]
        if pos + size > n:
            raise DecodeError(f'truncated operand for {name} at {label(start)}')
        raw = code[pos:pos + size]
        pos += size
        operand, text = _render(kind, raw, pos, resolver)
        out.append(Instruction(start, name, kind, operand, text))
    return out


def _render(kind, raw, next_pos, resolver):
    if kind == NONE:
        return None, ''
    if kind == I1:
        v = struct.unpack('<b', raw)[0]
        return v, str(v)
    if kind == I4:
        v = struct.unpack('<i', raw)[0]
        return v, str(v)
    if kind == I8:
        v = struct.unpack('<q', raw)[0]
        return v, str(v)
    if kind == R4:
        v = struct.unpack('<f', raw)[0]
        return v, repr(v)
    if kind == R8:
        v = struct.unpack('<d', raw)[0]
        return v, repr(v)
    if kind == VAR8:
        v = raw[0]
        return v, str(v)
    if kind == VAR16:
        v = struct.unpack('<H', raw)[0]
        return v, str(v)
    if kind == BR8:
        target = next_pos + struct.unpack('<b', raw)[0]
        return target, label(target)
    if kind == BR32:
        target = next_pos + struct.unpack('<i', raw)[0]
        return target, label(target)

    token = struct.unpack('<I', raw)[0]
    fallback = f'/* 0x{token:08x} */'
    method_name = {METHOD: 'method', FIELD: 'field', TYPE: 'type', TOKEN: 'token',
                   STRING: 'string', SIG: 'signature'}[kind]
    fn = getattr(resolver, method_name, None) if resolver is not None else None
    if fn is None:
        return token, fallback
    try:
        resolved = fn(token)
    except Exception:
        resolved = None
    if resolved is None:
        return token, fallback
    if kind == STRING:
        return token, '"' + _escape(resolved) + '"'
    return token, resolved


def render(instructions: List[Instruction]) -> List[str]:
    """ildasm-style lines: `IL_0007:  callvirt   instance string ...`."""
    lines = []
    for ins in instructions:
        if ins.text:
            lines.append(f'  {label(ins.offset)}:  {ins.opcode:<10} {ins.text}')
        else:
            lines.append(f'  {label(ins.offset)}:  {ins.opcode}')
    return lines
