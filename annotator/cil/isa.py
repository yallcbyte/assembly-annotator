"""CIL opcode knowledge base.

CIL is a stack machine, so each entry records how many operands it pops and
pushes as well as what it means. Those counts are what let explain.py model
the evaluation stack and name the arguments a call actually receives.

`pop`/`push` of VARIES means the count comes from a method signature.
"""

import re
from typing import NamedTuple, Optional

VARIES = -1

CATEGORIES = {
    'load':      {'label': 'Load / push',      'colour': '#4fc3f7'},
    'store':     {'label': 'Store / pop',      'colour': '#4db6ac'},
    'call':      {'label': 'Call',             'colour': '#ffb74d'},
    'control':   {'label': 'Control flow',     'colour': '#e57373'},
    'compare':   {'label': 'Comparison',       'colour': '#f06292'},
    'arith':     {'label': 'Arithmetic',       'colour': '#81c784'},
    'logic':     {'label': 'Bitwise / logic',  'colour': '#ba68c8'},
    'object':    {'label': 'Objects / arrays', 'colour': '#9fa8da'},
    'convert':   {'label': 'Conversion',       'colour': '#80cbc4'},
    'exception': {'label': 'Exceptions',       'colour': '#ff8a65'},
    'prefix':    {'label': 'Prefix',           'colour': '#90a4ae'},
    'other':     {'label': 'Other',            'colour': '#90a4ae'},
}


def _o(name, category, summary, template='', pop=0, push=0, detail=''):
    return {'name': name, 'category': category, 'summary': summary,
            'template': template, 'pop': pop, 'push': push, 'detail': detail}


OPCODES = {
    'nop':   _o('No operation', 'other', 'Do nothing',
                'Do nothing — a placeholder the compiler leaves for the debugger', 0, 0,
                'Debug builds are full of these; release builds usually are not.'),
    'break': _o('Breakpoint', 'other', 'Signal a debugger breakpoint',
                'Break to an attached debugger', 0, 0),
    'dup':   _o('Duplicate', 'load', 'Duplicate the top stack value',
                'Duplicate the value on top of the stack', 1, 2),
    'pop':   _o('Pop', 'store', 'Discard the top stack value',
                'Discard the value on top of the stack', 1, 0),

    # -- constants ----------------------------------------------------
    'ldnull': _o('Load null', 'load', 'Push a null reference', 'Push null', 0, 1),
    'ldstr':  _o('Load string', 'load', 'Push a string literal',
                 'Push the string literal {op}', 0, 1,
                 'String literals live in the #US metadata heap, so they survive into '
                 'the binary in readable form.'),
    'ldc.i4': _o('Load int32 constant', 'load', 'Push a 32-bit integer',
                 'Push the 32-bit constant {op}', 0, 1),
    'ldc.i8': _o('Load int64 constant', 'load', 'Push a 64-bit integer',
                 'Push the 64-bit constant {op}', 0, 1),
    'ldc.r4': _o('Load float32 constant', 'load', 'Push a 32-bit float',
                 'Push the single-precision constant {op}', 0, 1),
    'ldc.r8': _o('Load float64 constant', 'load', 'Push a 64-bit float',
                 'Push the double-precision constant {op}', 0, 1),

    # -- arguments and locals -----------------------------------------
    'ldarg':   _o('Load argument', 'load', 'Push an argument',
                  'Push argument {op}', 0, 1),
    'ldarga':  _o('Load argument address', 'load', 'Push the address of an argument',
                  'Push the address of argument {op}', 0, 1),
    'starg':   _o('Store argument', 'store', 'Pop into an argument',
                  'Pop the stack into argument {op}', 1, 0),
    'ldloc':   _o('Load local', 'load', 'Push a local variable',
                  'Push local {op}', 0, 1),
    'ldloca':  _o('Load local address', 'load', 'Push the address of a local',
                  'Push the address of local {op}', 0, 1),
    'stloc':   _o('Store local', 'store', 'Pop into a local variable',
                  'Pop the stack into local {op}', 1, 0),

    # -- fields --------------------------------------------------------
    'ldfld':   _o('Load field', 'load', 'Push an instance field',
                  'Push the field {op} of the object on the stack', 1, 1),
    'ldflda':  _o('Load field address', 'load', 'Push the address of an instance field',
                  'Push the address of field {op}', 1, 1),
    'stfld':   _o('Store field', 'store', 'Pop into an instance field',
                  'Store the top of the stack into field {op}', 2, 0),
    'ldsfld':  _o('Load static field', 'load', 'Push a static field',
                  'Push the static field {op}', 0, 1),
    'ldsflda': _o('Load static field address', 'load', 'Push the address of a static field',
                  'Push the address of static field {op}', 0, 1),
    'stsfld':  _o('Store static field', 'store', 'Pop into a static field',
                  'Store the top of the stack into static field {op}', 1, 0),

    # -- calls ---------------------------------------------------------
    'call':     _o('Call', 'call', 'Call a method directly',
                   'Call {op}', VARIES, VARIES,
                   'A direct, statically bound call. The target is fixed at compile time, '
                   'so no virtual dispatch happens.'),
    'callvirt': _o('Call virtual', 'call', 'Call a method with virtual dispatch',
                   'Call {op} on the object, resolving the override at run time', VARIES, VARIES,
                   'Dispatches on the object’s actual type and throws '
                   'NullReferenceException if it is null. C# uses it for most instance '
                   'calls even on non-virtual methods, precisely for that null check.'),
    'calli':    _o('Call indirect', 'call', 'Call through a function pointer',
                   'Call the function pointer on top of the stack', VARIES, VARIES,
                   'The target is only known at run time. Rare in compiler output, and a '
                   'common ingredient in obfuscators and native-code bridges.'),
    'newobj':   _o('New object', 'call', 'Allocate an object and run its constructor',
                   'Create a new {op}', VARIES, 1,
                   'Allocates, runs the constructor with the arguments on the stack, and '
                   'leaves the new reference behind.'),
    'ret':      _o('Return', 'control', 'Return from the method',
                   'Return to the caller', VARIES, 0),
    'jmp':      _o('Jump to method', 'call', 'Transfer control to another method',
                   'Abandon this method and transfer control to {op}', 0, 0,
                   'Replaces the current frame entirely. Almost never emitted by compilers.'),
    'ldftn':    _o('Load method pointer', 'load', 'Push a pointer to a method',
                   'Push a function pointer to {op}', 0, 1,
                   'Usually a delegate being constructed. Also how obfuscators build '
                   'indirect call tables.'),
    'ldvirtftn': _o('Load virtual method pointer', 'load',
                    'Push a pointer to a virtual method',
                    'Push a function pointer to the override of {op}', 1, 1),

    # -- objects, arrays, boxing ---------------------------------------
    'newarr':    _o('New array', 'object', 'Allocate a one-dimensional array',
                    'Allocate an array of {op}, with the length taken from the stack', 1, 1),
    'ldlen':     _o('Load array length', 'object', 'Push an array length',
                    'Push the length of the array on the stack', 1, 1),
    'ldelema':   _o('Load element address', 'object', 'Push the address of an array element',
                    'Push the address of an element of the array', 2, 1),
    'box':       _o('Box', 'object', 'Wrap a value type in an object',
                    'Box the value as {op} so it can be used as an object', 1, 1),
    'unbox':     _o('Unbox', 'object', 'Get the address of a boxed value',
                    'Unbox the object into a {op} pointer', 1, 1),
    'unbox.any': _o('Unbox any', 'object', 'Extract a boxed value',
                    'Unbox the object into a {op} value', 1, 1),
    'castclass': _o('Cast', 'object', 'Cast, throwing on failure',
                    'Cast the object to {op}, throwing InvalidCastException if it is not', 1, 1),
    'isinst':    _o('Type test', 'object', 'Test the type, pushing null on failure',
                    'Test whether the object is a {op}, pushing null if it is not', 1, 1,
                    'This is C#’s `as` operator and the first half of `is`.'),
    'initobj':   _o('Initialise object', 'object', 'Zero a value type',
                    'Zero-initialise the {op} at the address on the stack', 1, 0),
    'cpobj':     _o('Copy object', 'object', 'Copy a value type', 'Copy a {op} value', 2, 0),
    'ldobj':     _o('Load object', 'load', 'Push a value type from an address',
                    'Load the {op} value at the address on the stack', 1, 1),
    'stobj':     _o('Store object', 'store', 'Store a value type to an address',
                    'Store a {op} value to the address on the stack', 2, 0),
    'sizeof':    _o('Size of', 'object', 'Push the size of a type',
                    'Push the size in bytes of {op}', 0, 1),
    'ldtoken':   _o('Load metadata token', 'load', 'Push a metadata token',
                    'Push the metadata token for {op}', 0, 1,
                    'Feeds Type.GetTypeFromHandle and friends — the usual start of a '
                    'reflection sequence, and of array initialisation from static data.'),
    'localloc':  _o('Allocate on stack', 'object', 'Allocate from the local stack',
                    'Allocate space on the call stack (C# `stackalloc`)', 1, 1),
    'cpblk':     _o('Copy memory block', 'object', 'Copy raw memory',
                    'Copy a block of raw memory', 3, 0),
    'initblk':   _o('Initialise memory block', 'object', 'Fill raw memory',
                    'Fill a block of raw memory with a byte value', 3, 0),
    'mkrefany':  _o('Make typed reference', 'object', 'Build a typed reference', '', 1, 1),
    'refanyval': _o('Typed reference value', 'object', 'Read a typed reference', '', 1, 1),
    'refanytype': _o('Typed reference type', 'object', 'Read a typed reference type', '', 1, 1),
    'arglist':   _o('Argument list', 'other', 'Push the argument handle', '', 0, 1),

    # -- arithmetic -----------------------------------------------------
    'add': _o('Add', 'arith', 'Add the top two values', 'Add the top two stack values', 2, 1),
    'sub': _o('Subtract', 'arith', 'Subtract the top two values',
              'Subtract the top stack value from the one below it', 2, 1),
    'mul': _o('Multiply', 'arith', 'Multiply the top two values',
              'Multiply the top two stack values', 2, 1),
    'div': _o('Divide', 'arith', 'Divide, signed',
              'Divide the second stack value by the top one', 2, 1),
    'div.un': _o('Divide unsigned', 'arith', 'Divide, unsigned',
                 'Divide the second stack value by the top one, unsigned', 2, 1),
    'rem': _o('Remainder', 'arith', 'Remainder, signed',
              'Take the remainder of the division', 2, 1),
    'rem.un': _o('Remainder unsigned', 'arith', 'Remainder, unsigned',
                 'Take the unsigned remainder of the division', 2, 1),
    'neg': _o('Negate', 'arith', 'Negate the top value', 'Negate the top stack value', 1, 1),

    # -- logic -----------------------------------------------------------
    'and': _o('Bitwise AND', 'logic', 'Bitwise AND', 'Bitwise-AND the top two stack values', 2, 1),
    'or':  _o('Bitwise OR', 'logic', 'Bitwise OR', 'Bitwise-OR the top two stack values', 2, 1),
    'xor': _o('Bitwise XOR', 'logic', 'Bitwise XOR', 'Bitwise-XOR the top two stack values', 2, 1,
              'A loop built around XOR over a byte array is the commonest way .NET '
              'malware hides strings and payloads.'),
    'not': _o('Bitwise NOT', 'logic', 'Invert every bit', 'Invert every bit of the top value', 1, 1),
    'shl': _o('Shift left', 'logic', 'Shift left', 'Shift the value left', 2, 1),
    'shr': _o('Shift right', 'logic', 'Shift right, signed', 'Shift the value right, keeping its sign', 2, 1),
    'shr.un': _o('Shift right unsigned', 'logic', 'Shift right, unsigned',
                 'Shift the value right, filling with zeros', 2, 1),

    # -- comparison -------------------------------------------------------
    'ceq':    _o('Compare equal', 'compare', 'Push 1 if equal',
                 'Push 1 if the top two values are equal, otherwise 0', 2, 1),
    'cgt':    _o('Compare greater', 'compare', 'Push 1 if greater',
                 'Push 1 if the second value is greater, otherwise 0', 2, 1),
    'cgt.un': _o('Compare greater unsigned', 'compare', 'Push 1 if greater, unsigned',
                 'Push 1 if the second value is greater, unsigned', 2, 1),
    'clt':    _o('Compare less', 'compare', 'Push 1 if less',
                 'Push 1 if the second value is less, otherwise 0', 2, 1),
    'clt.un': _o('Compare less unsigned', 'compare', 'Push 1 if less, unsigned',
                 'Push 1 if the second value is less, unsigned', 2, 1),

    # -- control flow ------------------------------------------------------
    'br':      _o('Branch', 'control', 'Branch unconditionally', 'Jump to {op} — always taken', 0, 0),
    'brtrue':  _o('Branch if true', 'control', 'Branch when non-zero or non-null',
                  'Jump to {op} if the top value is non-zero or non-null', 1, 0),
    'brfalse': _o('Branch if false', 'control', 'Branch when zero or null',
                  'Jump to {op} if the top value is zero or null', 1, 0),
    'beq':     _o('Branch if equal', 'control', 'Branch when equal',
                  'Jump to {op} if the two values are equal', 2, 0),
    'bne.un':  _o('Branch if not equal', 'control', 'Branch when not equal',
                  'Jump to {op} if the two values differ', 2, 0),
    'bge':     _o('Branch if >=', 'control', 'Branch when greater or equal',
                  'Jump to {op} if the second value is greater than or equal to the top', 2, 0),
    'bgt':     _o('Branch if >', 'control', 'Branch when greater',
                  'Jump to {op} if the second value is greater than the top', 2, 0),
    'ble':     _o('Branch if <=', 'control', 'Branch when less or equal',
                  'Jump to {op} if the second value is less than or equal to the top', 2, 0),
    'blt':     _o('Branch if <', 'control', 'Branch when less',
                  'Jump to {op} if the second value is less than the top', 2, 0),
    'switch':  _o('Switch', 'control', 'Jump through a table',
                  'Jump to one of several targets based on the index on the stack', 1, 0,
                  'A compiled switch statement, or a state machine dispatch loop.'),
    'leave':   _o('Leave protected region', 'exception', 'Exit a try/catch block',
                  'Leave the protected region and jump to {op}', 0, 0,
                  'Used instead of `br` to exit a try, catch or filter; it runs any '
                  'intervening finally blocks first.'),
    'endfinally': _o('End finally', 'exception', 'End a finally block',
                     'End the finally block and continue unwinding', 0, 0),
    'endfilter':  _o('End filter', 'exception', 'End an exception filter',
                     'End the exception filter with the decision on the stack', 1, 0),
    'throw':   _o('Throw', 'exception', 'Throw an exception',
                  'Throw the exception on top of the stack', 1, 0),
    'rethrow': _o('Rethrow', 'exception', 'Rethrow the current exception',
                  'Rethrow the exception being handled, preserving its stack trace', 0, 0),
    'ckfinite': _o('Check finite', 'arith', 'Throw if not a finite number',
                   'Throw if the floating-point value is NaN or infinite', 1, 1),

    # -- prefixes -----------------------------------------------------------
    'constrained.': _o('Constrained prefix', 'prefix', 'Constrain the next virtual call',
                       'Constrain the following call to {op}', 0, 0,
                       'Lets callvirt work on a value type without boxing it first.'),
    'readonly.':    _o('Readonly prefix', 'prefix', 'The following array access is read-only', '', 0, 0),
    'volatile.':    _o('Volatile prefix', 'prefix', 'The following access is volatile',
                       'The following memory access is volatile', 0, 0),
    'unaligned.':   _o('Unaligned prefix', 'prefix', 'The following access may be unaligned', '', 0, 0),
    'tail.':        _o('Tail call prefix', 'prefix', 'Discard this frame before calling',
                       'Discard the current frame before making the following call', 0, 0),
    'no.':          _o('No-check prefix', 'prefix', 'Skip a runtime check', '', 0, 0),
}

# ---- generated families -------------------------------------------------

for _n in range(4):
    OPCODES[f'ldarg.{_n}'] = _o('Load argument', 'load', f'Push argument {_n}',
                                f'Push argument {_n}' + (' (`this`, in an instance method)'
                                                         if _n == 0 else ''), 0, 1)
    OPCODES[f'ldloc.{_n}'] = _o('Load local', 'load', f'Push local {_n}', f'Push local V_{_n}', 0, 1)
    OPCODES[f'stloc.{_n}'] = _o('Store local', 'store', f'Pop into local {_n}',
                                f'Pop the stack into local V_{_n}', 1, 0)
for _s in ('ldarg.s', 'ldarga.s', 'starg.s', 'ldloc.s', 'ldloca.s', 'stloc.s'):
    OPCODES[_s] = dict(OPCODES[_s.rsplit('.', 1)[0]])

OPCODES['ldc.i4.m1'] = _o('Load -1', 'load', 'Push -1', 'Push the constant -1', 0, 1)
OPCODES['ldc.i4.M1'] = OPCODES['ldc.i4.m1']
for _n in range(9):
    OPCODES[f'ldc.i4.{_n}'] = _o(f'Load {_n}', 'load', f'Push {_n}', f'Push the constant {_n}', 0, 1)
OPCODES['ldc.i4.s'] = dict(OPCODES['ldc.i4'])

# Element and indirect access families share one shape per suffix.
_ELEM = {'i1': 'signed byte', 'i2': '16-bit integer', 'i4': '32-bit integer',
         'i8': '64-bit integer', 'u1': 'unsigned byte', 'u2': 'unsigned 16-bit integer',
         'u4': 'unsigned 32-bit integer', 'u8': 'unsigned 64-bit integer',
         'r4': 'single-precision float', 'r8': 'double-precision float',
         'i': 'native integer', 'ref': 'object reference'}
for _sfx, _desc in _ELEM.items():
    OPCODES[f'ldelem.{_sfx}'] = _o('Load array element', 'object',
                                   f'Push a {_desc} array element',
                                   f'Push the {_desc} element at the index on the stack', 2, 1)
    OPCODES[f'stelem.{_sfx}'] = _o('Store array element', 'object',
                                   f'Store a {_desc} array element',
                                   f'Store a {_desc} into the array at the given index', 3, 0)
    OPCODES[f'ldind.{_sfx}'] = _o('Load indirect', 'load', f'Read a {_desc} from an address',
                                  f'Read a {_desc} from the address on the stack', 1, 1)
    OPCODES[f'stind.{_sfx}'] = _o('Store indirect', 'store', f'Write a {_desc} to an address',
                                  f'Write a {_desc} to the address on the stack', 2, 0)
OPCODES['ldelem'] = _o('Load array element', 'object', 'Push an array element',
                       'Push the {op} element at the index on the stack', 2, 1)
OPCODES['stelem'] = _o('Store array element', 'object', 'Store an array element',
                       'Store a {op} into the array at the given index', 3, 0)

_CONV = {'i1': 'signed byte', 'i2': '16-bit integer', 'i4': '32-bit integer',
         'i8': '64-bit integer', 'u1': 'unsigned byte', 'u2': 'unsigned 16-bit integer',
         'u4': 'unsigned 32-bit integer', 'u8': 'unsigned 64-bit integer',
         'r4': 'single-precision float', 'r8': 'double-precision float',
         'i': 'native integer', 'u': 'native unsigned integer', 'r.un': 'float, unsigned source'}
for _sfx, _desc in _CONV.items():
    OPCODES[f'conv.{_sfx}'] = _o('Convert', 'convert', f'Convert to {_desc}',
                                 f'Convert the top value to a {_desc}', 1, 1)
    OPCODES[f'conv.ovf.{_sfx}'] = _o('Convert checked', 'convert',
                                     f'Convert to {_desc}, throwing on overflow',
                                     f'Convert the top value to a {_desc}, '
                                     'throwing OverflowException if it does not fit', 1, 1)
    OPCODES[f'conv.ovf.{_sfx}.un'] = dict(OPCODES[f'conv.ovf.{_sfx}'])

for _base in ('add', 'sub', 'mul'):
    OPCODES[f'{_base}.ovf'] = _o(f'{_base.title()} checked', 'arith',
                                 f'{_base.title()}, throwing on overflow',
                                 f'{_base.title()} the top two values, throwing on overflow', 2, 1)
    OPCODES[f'{_base}.ovf.un'] = dict(OPCODES[f'{_base}.ovf'])

# Short-form branches behave exactly like their long forms.
for _b in ('br', 'brtrue', 'brfalse', 'beq', 'bne.un', 'bge', 'bgt', 'ble', 'blt', 'leave'):
    OPCODES[f'{_b}.s'] = dict(OPCODES[_b])
for _b in ('bge', 'bgt', 'ble', 'blt'):
    OPCODES[f'{_b}.un'] = dict(OPCODES[_b])
    OPCODES[f'{_b}.un.s'] = dict(OPCODES[_b])
OPCODES['brnull'] = dict(OPCODES['brfalse'])
OPCODES['brzero'] = dict(OPCODES['brfalse'])
OPCODES['brinst'] = dict(OPCODES['brtrue'])

CALL_OPCODES = {'call', 'callvirt', 'calli', 'newobj', 'jmp', 'ldftn', 'ldvirtftn'}
BRANCH_OPCODES = {k for k in OPCODES
                  if k.startswith(('br', 'beq', 'bne', 'bge', 'bgt', 'ble', 'blt', 'leave'))}


def lookup(opcode: str) -> Optional[dict]:
    return OPCODES.get((opcode or '').lower())


def category_of(opcode: str) -> str:
    entry = lookup(opcode)
    return entry['category'] if entry else 'other'


# ---- method signatures ---------------------------------------------------

class Signature(NamedTuple):
    raw: str
    instance: bool
    returns: str
    assembly: Optional[str]
    type_name: str          # `System.Net.WebClient`
    method: str             # `DownloadString`
    params: tuple           # ('string',)
    generic: bool

    @property
    def full_name(self) -> str:
        return f'{self.type_name}::{self.method}' if self.type_name else self.method

    @property
    def accessor(self):
        """('get'|'set', PropertyName) for a compiled C# property, else None."""
        for prefix in ('get_', 'set_'):
            if self.method.startswith(prefix) and len(self.method) > 4:
                return prefix[:3], self.method[4:]
        return None

    @property
    def short(self) -> str:
        owner = self.type_name.rsplit('.', 1)[-1] if self.type_name else ''
        # Show `Environment.UserName`, not the compiler's `get_UserName`.
        name = self.accessor[1] if self.accessor else self.method
        # `<LookupTypes>b__27_1` is the C# compiler's name for a lambda.
        lam = re.match(r'^<([^>]+)>b__', name)
        if lam:
            name = f'lambda in {lam.group(1)}'
        # Closure classes (`<>c`, `<>c__DisplayClass27_0`) add nothing a reader needs.
        owner = re.sub(r'/<>c(?:__DisplayClass[\w]*)?$', '', owner)
        # `Func`2<string,int32>` -> `Func<string,int32>`: the arity is noise.
        owner = re.sub(r'`\d+', '', owner)
        return f'{owner}.{name}' if owner else name

    @property
    def arg_count(self) -> int:
        """Stack slots the call consumes, counting `this` for instance calls."""
        return len(self.params) + (1 if self.instance else 0)

    @property
    def returns_value(self) -> bool:
        return self.returns not in ('void', '')


# `instance string [mscorlib]System.Net.WebClient::DownloadString(string)`
# The owner runs up to the first `::` and may contain generic arguments with
# commas (`Dictionary`2<string,int32>`); a return type may be two words
# (`native int`).
_SIG_RE = re.compile(
    r'^\s*(?P<mods>(?:instance\s+|explicit\s+|vararg\s+|class\s+|valuetype\s+)*)'
    r'(?P<ret>native\s+u?int\S*|\S+)\s+'
    r'(?:class\s+|valuetype\s+)?'          # ildasm repeats this before a generic owner
    r'(?:\[(?P<asm>[^\]]+)\])?'
    # Compiler-generated names start with `<...>` (`<Main>b__0_1`, `<>m__Finally1`).
    r'(?P<owner>[^\s(]+?)::(?P<method>(?:<[^>(]*>)?[^\s(<]*)'
    # Generic method arguments, allowing two levels of nesting.
    r'(?:<(?P<targs>(?:[^<>]|<(?:[^<>]|<[^<>]*>)*>)*)>)?'
    r'\s*\((?P<params>.*)\)\s*$',
    re.DOTALL)


def _split_params(text: str):
    """Split a parameter list on commas that are not inside <> or []."""
    parts, depth, cur = [], 0, []
    for ch in text:
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
    return tuple(p for p in parts if p)


def parse_signature(text: str) -> Optional[Signature]:
    """Parse an ildasm-style method reference, or return None."""
    if not text or '::' not in text:
        return None
    m = _SIG_RE.match(text.strip())
    if not m:
        return None
    mods = m.group('mods') or ''
    ret = m.group('ret')
    # `class Foo Bar::Baz()` -- the modifier swallowed the real return type.
    return Signature(
        raw=text.strip(),
        instance='instance' in mods,
        returns=ret,
        assembly=m.group('asm'),
        type_name=m.group('owner'),
        method=m.group('method'),
        params=_split_params(m.group('params') or ''),
        generic=bool(m.group('targs')),
    )
