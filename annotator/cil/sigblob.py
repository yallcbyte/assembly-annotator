"""Decode ECMA-335 signature blobs into ildasm-style type text.

Method, field and local-variable signatures are stored as compact byte
strings. Types that live in metadata tables are referenced by coded index;
the caller supplies `type_name(table_tag, row)` to turn those into names.
"""

import re
from typing import Callable, List, NamedTuple, Optional

PRIMITIVES = {
    0x01: 'void', 0x02: 'bool', 0x03: 'char', 0x04: 'int8', 0x05: 'uint8',
    0x06: 'int16', 0x07: 'uint16', 0x08: 'int32', 0x09: 'uint32',
    0x0A: 'int64', 0x0B: 'uint64', 0x0C: 'float32', 0x0D: 'float64',
    0x0E: 'string', 0x16: 'typedref', 0x18: 'native int', 0x19: 'native uint',
    0x1C: 'object',
}

# calling-convention flags
HASTHIS, EXPLICITTHIS, GENERIC = 0x20, 0x40, 0x10
FIELD, LOCAL_SIG, PROPERTY, GENERICINST = 0x06, 0x07, 0x08, 0x0A

# TypeDefOrRef coded index tags
TYPEDEF, TYPEREF, TYPESPEC = 0, 1, 2


class SigError(ValueError):
    pass


def _compact(type_text: str) -> str:
    """Short, space-free form of a type for use inside `delegate*<...>`."""
    t = _bare(type_text).replace('native int', 'nint').replace('native uint', 'nuint')
    t = re.sub(r'\[[^\]]+\]', '', t)
    return t.rsplit('.', 1)[-1].replace(' ', '')


def _generic_arg(type_text: str) -> str:
    """A generic argument as one token: bare, with `native int` as C#'s `nint`."""
    return _bare(type_text).replace('native uint', 'nuint').replace('native int', 'nint')


def _bare(type_text: str) -> str:
    for prefix in ('class ', 'valuetype '):
        if type_text.startswith(prefix):
            return type_text[len(prefix):]
    return type_text


class MethodSig(NamedTuple):
    instance: bool
    returns: str
    params: List[str]
    generic_params: int


class Reader:
    def __init__(self, data: bytes, type_name: Callable[[int, int], str], depth: int = 0):
        self.data = data
        self.pos = 0
        self.type_name = type_name
        self.depth = depth

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise SigError('signature ended early')
        b = self.data[self.pos]
        self.pos += 1
        return b

    def compressed(self) -> int:
        """ECMA-335 II.23.2 compressed unsigned integer."""
        b = self.byte()
        if b & 0x80 == 0:
            return b
        if b & 0xC0 == 0x80:
            return ((b & 0x3F) << 8) | self.byte()
        if b & 0xE0 == 0xC0:
            return ((b & 0x1F) << 24) | (self.byte() << 16) | (self.byte() << 8) | self.byte()
        raise SigError(f'bad compressed integer lead byte 0x{b:02x}')

    def compressed_signed(self) -> int:
        start = self.pos
        b = self.data[start] if start < len(self.data) else 0
        raw = self.compressed()
        width = 7 if b & 0x80 == 0 else (14 if b & 0xC0 == 0x80 else 29)
        negative = raw & 1
        value = raw >> 1
        return value - (1 << (width - 1)) if negative else value

    def type_def_or_ref(self) -> str:
        coded = self.compressed()
        tag, row = coded & 0x3, coded >> 2
        return self.type_name(tag, row)

    def type(self) -> str:
        if self.depth > 40:
            raise SigError('signature nests too deeply')
        b = self.byte()
        if b in PRIMITIVES:
            return PRIMITIVES[b]
        if b == 0x0F:                       # ptr
            return self._nested() + '*'
        if b == 0x10:                       # byref
            return self._nested() + '&'
        if b == 0x11:                       # valuetype
            return 'valuetype ' + self.type_def_or_ref()
        if b == 0x12:                       # class
            return 'class ' + self.type_def_or_ref()
        if b == 0x13:                       # var (type generic parameter)
            return f'!{self.compressed()}'
        if b == 0x1E:                       # mvar (method generic parameter)
            return f'!!{self.compressed()}'
        if b == 0x1D:                       # szarray
            return self._nested() + '[]'
        if b == 0x14:                       # general array
            element = self._nested()
            rank = self.compressed()
            for _ in range(self.compressed()):
                self.compressed()           # sizes
            for _ in range(self.compressed()):
                self.compressed_signed()    # lower bounds
            return element + '[' + ',' * max(0, rank - 1) + ']'
        if b == 0x15:                       # genericinst
            kind = self.byte()
            owner = self.type_def_or_ref()
            # Arguments are written bare (`List`1<string>`, not `<class X>`) so
            # the whole type stays one space-free token for the text parser.
            args = [_generic_arg(self._nested()) for _ in range(self.compressed())]
            prefix = 'valuetype ' if kind == 0x11 else 'class '
            return f'{prefix}{owner}<{",".join(args)}>'
        if b == 0x1B:                       # fnptr
            # Written the C# 9 way, `delegate*<arg,...,ret>`, as one space-free
            # token: ildasm's `method ret *(args)` breaks every signature it
            # appears in for a text parser.
            sig = method(self.data[self.pos:], self.type_name, self.depth + 1, reader=self)
            parts = [_compact(t) for t in sig.params + [sig.returns]]
            return f'delegate*<{",".join(parts)}>'
        if b in (0x1F, 0x20):               # cmod_reqd / cmod_opt: skip the modifier
            self.type_def_or_ref()
            return self.type()
        if b == 0x41:                       # sentinel (vararg boundary)
            return self.type()
        if b == 0x45:                       # pinned
            return self.type() + ' pinned'
        raise SigError(f'unknown element type 0x{b:02x}')

    def _nested(self) -> str:
        self.depth += 1
        try:
            return self.type()
        finally:
            self.depth -= 1


def method(data: bytes, type_name, depth: int = 0, reader: Optional[Reader] = None) -> MethodSig:
    r = reader or Reader(data, type_name, depth)
    conv = r.byte()
    generic = r.compressed() if conv & GENERIC else 0
    count = r.compressed()
    if count > 512:
        raise SigError('implausible parameter count')
    returns = r.type()
    params = []
    for _ in range(count):
        params.append(r.type())
    return MethodSig(bool(conv & HASTHIS), returns, params, generic)


def field(data: bytes, type_name) -> str:
    r = Reader(data, type_name)
    if r.byte() != FIELD:
        raise SigError('not a field signature')
    return r.type()


def locals_sig(data: bytes, type_name) -> List[str]:
    r = Reader(data, type_name)
    if r.byte() != LOCAL_SIG:
        raise SigError('not a local-variable signature')
    count = r.compressed()
    if count > 65535:
        raise SigError('implausible local count')
    return [r.type() for _ in range(count)]


def type_spec(data: bytes, type_name) -> str:
    return Reader(data, type_name).type()


def method_spec(data: bytes, type_name) -> List[str]:
    r = Reader(data, type_name)
    if r.byte() != GENERICINST:
        raise SigError('not a method instantiation')
    return [r.type() for _ in range(r.compressed())]
