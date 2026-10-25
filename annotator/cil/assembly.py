"""Open a .NET assembly and turn its methods into annotated IL.

Wraps dnfile: resolves metadata tokens to ildasm-style names, decodes method
bodies, and scans every method against the CIL rules so the browser can show
where in an assembly the interesting calls are.

Everything here parses; nothing executes. Untrusted input is expected, so
every lookup tolerates missing rows and malformed blobs.
"""

import hashlib
import struct
from typing import Dict, List, Optional

try:
    import dnfile
    AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without dnfile
    dnfile = None
    AVAILABLE = False

from . import il_decoder, isa, sigblob
from .patterns import CilContext, run_rules

MAX_ASSEMBLY_BYTES = 16 * 1024 * 1024
MAX_METHOD_BYTES = 256 * 1024

# MethodAttributes
_ACCESS = {1: 'private', 2: 'famandassem', 3: 'assembly', 4: 'family',
           5: 'famorassem', 6: 'public'}
STATIC, FINAL, VIRTUAL, HIDEBYSIG = 0x10, 0x20, 0x40, 0x80
ABSTRACT, SPECIALNAME, PINVOKE = 0x400, 0x800, 0x2000

# token table ids (high byte)
T_TYPEREF, T_TYPEDEF, T_FIELD, T_METHOD = 0x01, 0x02, 0x04, 0x06
T_MEMBERREF, T_SIG, T_TYPESPEC, T_METHODSPEC, T_STRING = 0x0A, 0x11, 0x1B, 0x2B, 0x70

EH_KINDS = {0: 'catch', 1: 'filter', 2: 'finally', 4: 'fault'}


class AssemblyError(ValueError):
    """Raised for input that is not a usable .NET assembly."""


def _s(item) -> str:
    """dnfile heap strings expose `.value`; fall back to str()."""
    if item is None:
        return ''
    value = getattr(item, 'value', item)
    return value if isinstance(value, str) else str(value)


def _blob(item) -> bytes:
    if item is None:
        return b''
    for attr in ('value_bytes', 'value', 'raw_data'):
        data = getattr(item, attr, None)
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
    return b''


def _rows(table) -> list:
    return list(table.rows) if table is not None else []


def _index(ref) -> int:
    """1-based row index of a dnfile table reference, 0 if absent."""
    return getattr(ref, 'row_index', 0) or 0


def _table(ref) -> str:
    t = getattr(ref, 'table', None)
    return getattr(t, 'name', '') if t is not None else ''


class Assembly:
    def __init__(self, data: bytes):
        if not AVAILABLE:
            raise AssemblyError('.NET support needs the `dnfile` package: pip install dnfile')
        if len(data) > MAX_ASSEMBLY_BYTES:
            raise AssemblyError(f'File is over the {MAX_ASSEMBLY_BYTES // (1024 * 1024)} MB limit.')
        if data[:2] != b'MZ':
            raise AssemblyError('Not a Windows PE file (no MZ header).')
        try:
            self.pe = dnfile.dnPE(data=data)
        except Exception as exc:
            raise AssemblyError(f'Could not parse the PE file: {type(exc).__name__}.')
        if getattr(self.pe, 'net', None) is None or self.pe.net.mdtables is None:
            raise AssemblyError('This is a native PE file, not a .NET assembly. '
                                'Only .NET assemblies can be opened here.')

        self.sha256 = hashlib.sha256(data).hexdigest()
        self.md = self.pe.net.mdtables
        self._name_cache: Dict[int, str] = {}
        self._typedefs = _rows(self.md.TypeDef)
        self._methods = _rows(self.md.MethodDef)
        self._fields = _rows(getattr(self.md, 'Field', None))
        self._params = _rows(getattr(self.md, 'Param', None))
        self._typerefs = _rows(self.md.TypeRef)
        self._typespecs = _rows(getattr(self.md, 'TypeSpec', None))
        self._memberrefs = _rows(self.md.MemberRef)
        self._methodspecs = _rows(getattr(self.md, 'MethodSpec', None))
        self._sigs = _rows(getattr(self.md, 'StandAloneSig', None))

        self._enclosing = {}
        for row in _rows(getattr(self.md, 'NestedClass', None)):
            self._enclosing[_index(row.NestedClass)] = _index(row.EnclosingClass)

        # Which type each method and field belongs to.
        self._method_owner, self._field_owner = {}, {}
        for t, row in enumerate(self._typedefs, start=1):
            for ref in getattr(row, 'MethodList', None) or []:
                self._method_owner[_index(ref)] = t
            for ref in getattr(row, 'FieldList', None) or []:
                self._field_owner[_index(ref)] = t

        self._pinvoke = {}
        for row in _rows(getattr(self.md, 'ImplMap', None)):
            if _table(row.MemberForwarded) == 'MethodDef':
                scope = getattr(row.ImportScope, 'row', None)
                self._pinvoke[_index(row.MemberForwarded)] = {
                    'name': _s(row.ImportName),
                    'dll': _s(getattr(scope, 'Name', None)) or '?',
                }

    # ---- type names ----------------------------------------------------
    def typedef_name(self, row_index: int) -> str:
        if not 0 < row_index <= len(self._typedefs):
            return f'TypeDef#{row_index}'
        row = self._typedefs[row_index - 1]
        name = _s(row.TypeName)
        outer = self._enclosing.get(row_index)
        if outer and outer != row_index:
            return f'{self.typedef_name(outer)}/{name}'
        ns = _s(row.TypeNamespace)
        return f'{ns}.{name}' if ns else name

    def typeref_name(self, row_index: int, depth: int = 0) -> str:
        if not 0 < row_index <= len(self._typerefs) or depth > 20:
            return f'TypeRef#{row_index}'
        row = self._typerefs[row_index - 1]
        ns, name = _s(row.TypeNamespace), _s(row.TypeName)
        local = f'{ns}.{name}' if ns else name
        scope = row.ResolutionScope
        kind = _table(scope)
        if kind == 'AssemblyRef':
            return f'[{_s(getattr(scope.row, "Name", None))}]{local}'
        if kind == 'TypeRef':
            return f'{self.typeref_name(_index(scope), depth + 1)}/{name}'
        return local

    def _type_from_coded(self, tag: int, row: int) -> str:
        """Callback for signature blobs: TypeDefOrRef coded index -> name."""
        if tag == sigblob.TYPEDEF:
            return self.typedef_name(row)
        if tag == sigblob.TYPEREF:
            return self.typeref_name(row)
        if tag == sigblob.TYPESPEC:
            return self.typespec_name(row)
        return f'?{tag}:{row}'

    def typespec_name(self, row_index: int) -> str:
        if not 0 < row_index <= len(self._typespecs):
            return f'TypeSpec#{row_index}'
        try:
            return sigblob.type_spec(_blob(self._typespecs[row_index - 1].Signature),
                                     self._type_from_coded)
        except sigblob.SigError:
            return f'TypeSpec#{row_index}'

    def _owner_text(self, ref) -> str:
        kind, row = _table(ref), _index(ref)
        if kind == 'TypeRef':
            return self.typeref_name(row)
        if kind == 'TypeDef':
            return self.typedef_name(row)
        if kind == 'TypeSpec':
            return sigblob._bare(self.typespec_name(row))
        if kind == 'ModuleRef':
            return f'[.module {_s(getattr(ref.row, "Name", None))}]'
        if kind == 'MethodDef':
            owner = self._method_owner.get(row)
            return self.typedef_name(owner) if owner else '<Module>'
        return '?'

    # ---- resolver interface used by il_decoder ------------------------------
    def type(self, token: int) -> Optional[str]:
        table, row = token >> 24, token & 0xFFFFFF
        if table == T_TYPEDEF:
            return self.typedef_name(row)
        if table == T_TYPEREF:
            return self.typeref_name(row)
        if table == T_TYPESPEC:
            return self.typespec_name(row)
        return None

    def string(self, token: int) -> Optional[str]:
        if token >> 24 != T_STRING:
            return None
        item = self.pe.net.user_strings.get(token & 0xFFFFFF) if self.pe.net.user_strings else None
        return _s(item) if item is not None else None

    def field(self, token: int) -> Optional[str]:
        table, row = token >> 24, token & 0xFFFFFF
        if table == T_FIELD and 0 < row <= len(self._fields):
            f = self._fields[row - 1]
            ftype = self._safe(lambda: sigblob.field(_blob(f.Signature), self._type_from_coded))
            owner = self._field_owner.get(row)
            owner_name = self.typedef_name(owner) if owner else '<Module>'
            return f'{ftype or "?"} {owner_name}::{_s(f.Name)}'
        if table == T_MEMBERREF and 0 < row <= len(self._memberrefs):
            m = self._memberrefs[row - 1]
            ftype = self._safe(lambda: sigblob.field(_blob(m.Signature), self._type_from_coded))
            return f'{ftype or "?"} {self._owner_text(m.Class)}::{_s(m.Name)}'
        return None

    def method(self, token: int) -> Optional[str]:
        if token in self._name_cache:
            return self._name_cache[token]
        text = self._method_text(token)
        self._name_cache[token] = text
        return text

    def token(self, token: int) -> Optional[str]:
        """ldtoken may name a type, a method or a field."""
        table = token >> 24
        if table in (T_TYPEDEF, T_TYPEREF, T_TYPESPEC):
            return self.type(token)
        if table in (T_METHOD, T_METHODSPEC):
            return 'method ' + (self.method(token) or '?')
        if table == T_FIELD:
            return 'field ' + (self.field(token) or '?')
        if table == T_MEMBERREF:
            row = token & 0xFFFFFF
            if 0 < row <= len(self._memberrefs):
                sig = _blob(self._memberrefs[row - 1].Signature)
                if sig[:1] == bytes([sigblob.FIELD]):
                    return 'field ' + (self.field(token) or '?')
            return 'method ' + (self.method(token) or '?')
        return None

    def signature(self, token: int) -> Optional[str]:
        """calli takes a StandAloneSig."""
        if token >> 24 != T_SIG:
            return None
        row = token & 0xFFFFFF
        if not 0 < row <= len(self._sigs):
            return None
        sig = self._safe(lambda: sigblob.method(_blob(self._sigs[row - 1].Signature),
                                                self._type_from_coded))
        return f'{sig.returns}({", ".join(sig.params)})' if sig else None

    # ---- method text -----------------------------------------------------------
    def _method_text(self, token: int) -> Optional[str]:
        table, row = token >> 24, token & 0xFFFFFF
        if table == T_METHOD and 0 < row <= len(self._methods):
            m = self._methods[row - 1]
            owner = self._method_owner.get(row)
            owner_name = self.typedef_name(owner) if owner else '<Module>'
            return self._format_call(_blob(m.Signature), owner_name, _s(m.Name))
        if table == T_MEMBERREF and 0 < row <= len(self._memberrefs):
            m = self._memberrefs[row - 1]
            return self._format_call(_blob(m.Signature), self._owner_text(m.Class), _s(m.Name))
        if table == T_METHODSPEC and 0 < row <= len(self._methodspecs):
            spec = self._methodspecs[row - 1]
            base_ref = spec.Method
            base_token = ((T_METHOD if _table(base_ref) == 'MethodDef' else T_MEMBERREF) << 24
                          | _index(base_ref))
            base = self.method(base_token)
            args = self._safe(lambda: sigblob.method_spec(_blob(spec.Instantiation),
                                                          self._type_from_coded))
            if base and args and '(' in base:
                head, tail = base.split('(', 1)
                return f'{head}<{",".join(sigblob._bare(a) for a in args)}>({tail}'
            return base
        return None

    def _format_call(self, blob: bytes, owner: str, name: str) -> str:
        sig = self._safe(lambda: sigblob.method(blob, self._type_from_coded))
        if sig is None:
            return f'? {owner}::{name}(?)'
        inst = 'instance ' if sig.instance else ''
        # ildasm repeats `class` before a generic owner; the parser expects it.
        owner_prefix = 'class ' if '`' in owner and '<' in owner else ''
        return f'{inst}{sig.returns} {owner_prefix}{owner}::{name}({", ".join(sig.params)})'

    @staticmethod
    def _safe(fn):
        try:
            return fn()
        except (sigblob.SigError, struct.error, IndexError, AttributeError, TypeError):
            return None

    # ---- method listing ----------------------------------------------------------
    def method_info(self, row: int) -> dict:
        m = self._methods[row - 1]
        flags = getattr(m.struct, 'Flags', 0) or 0
        owner = self._method_owner.get(row)
        sig = self._safe(lambda: sigblob.method(_blob(m.Signature), self._type_from_coded))
        params = self._param_names(m)
        shown_params = ', '.join(
            f'{t} {params.get(i + 1)}' if params.get(i + 1) else t
            for i, t in enumerate(sig.params if sig else []))
        name = _s(m.Name)
        return {
            'id': row,
            'token': f'0x{(T_METHOD << 24) | row:08x}',
            'name': name,
            'type': self.typedef_name(owner) if owner else '<Module>',
            'display': f'{sig.returns if sig else "?"} {name}({shown_params})',
            'static': bool(flags & STATIC),
            'abstract': bool(flags & ABSTRACT),
            'pinvoke': row in self._pinvoke,
            'has_body': bool(getattr(m, 'Rva', 0)) and not flags & ABSTRACT,
            'access': _ACCESS.get(flags & 0x7, ''),
            'flags': flags,
        }

    def _param_names(self, method_row) -> Dict[int, str]:
        names = {}
        for ref in getattr(method_row, 'ParamList', None) or []:
            i = _index(ref)
            if 0 < i <= len(self._params):
                p = self._params[i - 1]
                seq = getattr(p, 'Sequence', 0)
                if seq:
                    names[seq] = _s(p.Name)
        return names

    def entry_point(self) -> Optional[int]:
        try:
            tok = self.pe.net.struct.EntryPointTokenOrRva
        except AttributeError:
            return None
        if tok and tok >> 24 == T_METHOD:
            return tok & 0xFFFFFF
        return None

    # ---- bodies ---------------------------------------------------------------------
    def body(self, row: int):
        """Return (code bytes, maxstack, locals, exception clauses) or raise."""
        m = self._methods[row - 1]
        rva = getattr(m, 'Rva', 0)
        if not rva:
            raise AssemblyError('This method has no IL body (abstract, extern or P/Invoke).')
        try:
            head = self.pe.get_data(rva, 12)
        except Exception:
            raise AssemblyError('The method body points outside the file.')
        if not head:
            raise AssemblyError('Empty method header.')
        first = head[0]
        if first & 0x3 == 0x2:                                 # tiny header
            size = first >> 2
            code = self.pe.get_data(rva + 1, size)
            return code, 8, [], []
        if first & 0x3 != 0x3:
            raise AssemblyError(f'Unrecognised method header byte 0x{first:02x}.')
        flags_size, maxstack, size, local_tok = struct.unpack_from('<HHII', head, 0)
        header = (flags_size >> 12) * 4
        if size > MAX_METHOD_BYTES:
            raise AssemblyError(f'Method body is {size} bytes, over the limit.')
        code = self.pe.get_data(rva + header, size)
        locals_ = self._locals(local_tok)
        clauses = self._exception_clauses(rva + header + size) if flags_size & 0x8 else []
        return code, maxstack, locals_, clauses

    def _locals(self, token: int) -> List[str]:
        if not token or token >> 24 != T_SIG:
            return []
        row = token & 0xFFFFFF
        if not 0 < row <= len(self._sigs):
            return []
        return self._safe(lambda: sigblob.locals_sig(_blob(self._sigs[row - 1].Signature),
                                                     self._type_from_coded)) or []

    def _exception_clauses(self, at: int) -> List[dict]:
        clauses = []
        pos = (at + 3) & ~3
        for _ in range(8):                                     # data sections
            try:
                head = self.pe.get_data(pos, 4)
            except Exception:
                break
            if len(head) < 4:
                break
            kind = head[0]
            fat = bool(kind & 0x40)
            size = (head[1] | head[2] << 8 | head[3] << 16) if fat else head[1]
            if kind & 0x1 and size >= 4:
                width = 24 if fat else 12
                count = min((size - 4) // width, 256)
                try:
                    raw = self.pe.get_data(pos + 4, count * width)
                except Exception:
                    break
                for i in range(count):
                    if fat:
                        f, to, tl, ho, hl, extra = struct.unpack_from('<6I', raw, i * width)
                    else:
                        f, to, tl, ho, hl, extra = struct.unpack_from('<HHBHBI', raw, i * width)
                    clauses.append({'kind': EH_KINDS.get(f & 0x7, 'catch'),
                                    'try': (to, to + tl), 'handler': (ho, ho + hl),
                                    'class': self.type(extra) if f & 0x7 == 0 else None})
            if not kind & 0x80:
                break
            pos += size
        return clauses

    def disassemble(self, row: int) -> str:
        """ildasm-style listing for one method, ready for the CIL pipeline."""
        if not 0 < row <= len(self._methods):
            raise AssemblyError('No such method.')
        info = self.method_info(row)
        flags = info['flags']
        words = [info['access']] if info['access'] else []
        if flags & HIDEBYSIG:
            words.append('hidebysig')
        if flags & STATIC:
            words.append('static')
        if flags & VIRTUAL:
            words.append('virtual')
        if row in self._pinvoke:
            words.append(f'pinvokeimpl("{self._pinvoke[row]["dll"]}")')
        header = [f'// {info["type"]}::{info["name"]}   (token {info["token"]})',
                  f'.method {" ".join(words)} {info["display"]} cil managed', '{']

        if not info['has_body']:
            reason = 'P/Invoke into ' + self._pinvoke[row]['dll'] if row in self._pinvoke \
                else 'no IL body'
            return '\n'.join(header + [f'  // {reason}', '}'])

        code, maxstack, locals_, clauses = self.body(row)
        lines = list(header)
        if row == self.entry_point():
            lines.append('  .entrypoint')
        lines.append(f'  .maxstack  {maxstack}')
        if locals_:
            slots = ',\n                '.join(f'[{i}] {t} V_{i}' for i, t in enumerate(locals_))
            lines.append(f'  .locals init ({slots})')
        for c in clauses:
            what = c['kind'] + (f' {c["class"]}' if c.get('class') else '')
            lines.append(f'  // .try {il_decoder.label(c["try"][0])} to {il_decoder.label(c["try"][1])} '
                         f'{what} handler {il_decoder.label(c["handler"][0])} '
                         f'to {il_decoder.label(c["handler"][1])}')
        try:
            instructions = il_decoder.decode(code, self)
            lines.extend(il_decoder.render(instructions))
        except il_decoder.DecodeError as exc:
            lines.append(f'  // decoding stopped: {exc}')
        lines.append('}')
        return '\n'.join(lines)

    # ---- whole-assembly scan ---------------------------------------------------------
    def scan(self, max_methods: int = 20000) -> dict:
        methods, types, findings = [], {}, {}
        for row in range(1, min(len(self._methods), max_methods) + 1):
            info = self.method_info(row)
            calls, opcodes, decls = [], [], []
            if row in self._pinvoke:
                p = self._pinvoke[row]
                decls.append((row, f'pinvokeimpl("{p["dll"]}") {p["name"]}'))
                calls.append((row, p['name']))
            if info['has_body']:
                try:
                    code, _, _, _ = self.body(row)
                    for ins in il_decoder.decode(code, self):
                        opcodes.append((row, ins.opcode))
                        if ins.kind == il_decoder.METHOD and ins.text:
                            sig = isa.parse_signature(ins.text)
                            calls.append((row, sig.full_name if sig else ins.text))
                        elif ins.kind == il_decoder.STRING and ins.text:
                            calls.append((row, ins.text.strip('"')))
                except (AssemblyError, il_decoder.DecodeError, Exception):
                    info['decode_error'] = True
            hits = run_rules(CilContext.from_parts(calls, opcodes, decls))
            info['findings'] = [h['id'] for h in hits]
            info['severity'] = _worst(h['severity'] for h in hits)
            info['calls'] = len([c for c in calls if '::' in c[1]])
            for h in hits:
                agg = findings.setdefault(h['id'], {**{k: h[k] for k in
                                                       ('id', 'name', 'description',
                                                        'severity', 'category')},
                                                    'methods': [], 'evidence': set()})
                agg['methods'].append(row)
                agg['evidence'].update(h['evidence'])
            info.pop('flags', None)
            methods.append(info)
            types.setdefault(info['type'], []).append(row)

        order = {'warning': 0, 'notable': 1, 'info': 2}
        agg_list = sorted(findings.values(),
                          key=lambda f: (order.get(f['severity'], 3), f['name']))
        for f in agg_list:
            f['evidence'] = sorted(f['evidence'])[:8]
            f['method_count'] = len(f['methods'])
            f['methods'] = f['methods'][:200]

        asm_row = _rows(getattr(self.md, 'Assembly', None))
        name, version = '', ''
        if asm_row:
            a = asm_row[0]
            name = _s(a.Name)
            version = '.'.join(str(getattr(a, k, 0)) for k in
                               ('MajorVersion', 'MinorVersion', 'BuildNumber', 'RevisionNumber'))
        return {
            'sha256': self.sha256,
            'name': name or '(module)',
            'version': version,
            'kind': 'exe' if self.pe.is_exe() and not self.pe.is_dll() else 'dll',
            'entry_point': self.entry_point(),
            'references': [_s(r.Name) for r in _rows(getattr(self.md, 'AssemblyRef', None))],
            'pinvokes': [{'method': row, **p} for row, p in sorted(self._pinvoke.items())],
            'types': [{'name': t, 'methods': rows} for t, rows in types.items()],
            'methods': methods,
            'findings': agg_list,
            'counts': {
                'types': len(self._typedefs),
                'methods': len(self._methods),
                'with_body': sum(1 for m in methods if m['has_body']),
                'flagged': sum(1 for m in methods if m['findings']),
                'pinvokes': len(self._pinvoke),
                'references': len(_rows(getattr(self.md, 'AssemblyRef', None))),
            },
        }


def _worst(severities) -> Optional[str]:
    order = {'warning': 0, 'notable': 1, 'info': 2}
    found = sorted(severities, key=lambda s: order.get(s, 3))
    return found[0] if found else None
