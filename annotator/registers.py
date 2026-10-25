"""Register knowledge base.

Maps register names to a human-readable role so explanations can say
"the counter register ECX" instead of just echoing the token back.
"""

# role, width in bits, canonical 64-bit parent
_X86 = {
    # 64-bit general purpose
    'rax': ('accumulator / return value', 64, 'rax'),
    'rbx': ('general purpose (callee-saved)', 64, 'rbx'),
    'rcx': ('counter / 4th integer argument', 64, 'rcx'),
    'rdx': ('data / 3rd integer argument', 64, 'rdx'),
    'rsi': ('source index / 2nd integer argument', 64, 'rsi'),
    'rdi': ('destination index / 1st integer argument', 64, 'rdi'),
    'rbp': ('base pointer (stack frame base)', 64, 'rbp'),
    'rsp': ('stack pointer (top of stack)', 64, 'rsp'),
    'rip': ('instruction pointer', 64, 'rip'),
    # 32-bit
    'eax': ('accumulator / return value', 32, 'rax'),
    'ebx': ('general purpose (callee-saved)', 32, 'rbx'),
    'ecx': ('counter (loop counter)', 32, 'rcx'),
    'edx': ('data / high half of multiply', 32, 'rdx'),
    'esi': ('source index (string source)', 32, 'rsi'),
    'edi': ('destination index (string destination)', 32, 'rdi'),
    'ebp': ('base pointer (stack frame base)', 32, 'rbp'),
    'esp': ('stack pointer (top of stack)', 32, 'rsp'),
    'eip': ('instruction pointer', 32, 'rip'),
    # 16-bit
    'ax': ('accumulator, low 16 bits', 16, 'rax'),
    'bx': ('general purpose, low 16 bits', 16, 'rbx'),
    'cx': ('counter, low 16 bits', 16, 'rcx'),
    'dx': ('data, low 16 bits', 16, 'rdx'),
    'si': ('source index, low 16 bits', 16, 'rsi'),
    'di': ('destination index, low 16 bits', 16, 'rdi'),
    'bp': ('base pointer, low 16 bits', 16, 'rbp'),
    'sp': ('stack pointer, low 16 bits', 16, 'rsp'),
    # 8-bit
    'al': ('accumulator, lowest byte', 8, 'rax'),
    'ah': ('accumulator, bits 8-15', 8, 'rax'),
    'bl': ('general purpose, lowest byte', 8, 'rbx'),
    'bh': ('general purpose, bits 8-15', 8, 'rbx'),
    'cl': ('counter, lowest byte (shift count)', 8, 'rcx'),
    'ch': ('counter, bits 8-15', 8, 'rcx'),
    'dl': ('data, lowest byte', 8, 'rdx'),
    'dh': ('data, bits 8-15', 8, 'rdx'),
    'sil': ('source index, lowest byte', 8, 'rsi'),
    'dil': ('destination index, lowest byte', 8, 'rdi'),
    # segment
    'cs': ('code segment selector', 16, 'cs'),
    'ds': ('data segment selector', 16, 'ds'),
    'es': ('extra segment selector', 16, 'es'),
    'fs': ('extra segment (thread-local storage on Linux)', 16, 'fs'),
    'gs': ('extra segment (thread-local storage on Windows)', 16, 'gs'),
    'ss': ('stack segment selector', 16, 'ss'),
}

# r8..r15 and their sub-registers
for _n in range(8, 16):
    _X86[f'r{_n}'] = (f'general purpose r{_n}', 64, f'r{_n}')
    _X86[f'r{_n}d'] = (f'general purpose r{_n}, low 32 bits', 32, f'r{_n}')
    _X86[f'r{_n}w'] = (f'general purpose r{_n}, low 16 bits', 16, f'r{_n}')
    _X86[f'r{_n}b'] = (f'general purpose r{_n}, lowest byte', 8, f'r{_n}')

# SIMD
for _n in range(16):
    _X86[f'xmm{_n}'] = (f'128-bit SIMD register xmm{_n}', 128, f'xmm{_n}')
    _X86[f'ymm{_n}'] = (f'256-bit SIMD register ymm{_n}', 256, f'ymm{_n}')

_ARM = {
    'sp': ('stack pointer', 64, 'sp'),
    'lr': ('link register (return address)', 64, 'lr'),
    'pc': ('program counter', 64, 'pc'),
    'fp': ('frame pointer', 64, 'fp'),
    'cpsr': ('current program status register (flags)', 32, 'cpsr'),
}
for _n in range(31):
    _ARM[f'x{_n}'] = (f'64-bit general purpose x{_n}', 64, f'x{_n}')
    _ARM[f'w{_n}'] = (f'low 32 bits of x{_n}', 32, f'x{_n}')
for _n in range(16):
    _ARM[f'r{_n}'] = (f'32-bit general purpose r{_n}', 32, f'r{_n}')

_MIPS = {
    'zero': ('hardwired zero', 32, 'zero'), 'at': ('assembler temporary', 32, 'at'),
    'gp': ('global pointer', 32, 'gp'), 'sp': ('stack pointer', 32, 'sp'),
    'fp': ('frame pointer', 32, 'fp'), 'ra': ('return address', 32, 'ra'),
}
for _n in range(2):
    _MIPS[f'v{_n}'] = (f'return value v{_n}', 32, f'v{_n}')
for _n in range(4):
    _MIPS[f'a{_n}'] = (f'argument a{_n}', 32, f'a{_n}')
for _n in range(10):
    _MIPS[f't{_n}'] = (f'temporary t{_n}', 32, f't{_n}')
for _n in range(8):
    _MIPS[f's{_n}'] = (f'saved register s{_n}', 32, f's{_n}')

ARCH_REGISTERS = {'x86': _X86, 'arm': _ARM, 'mips': _MIPS}

# Calling-convention argument order, used to narrate `call` sites.
ARG_ORDER = {
    'x86-64-sysv': ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'],
    'x86-64-ms': ['rcx', 'rdx', 'r8', 'r9'],
    'arm': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
}


def normalise(token: str) -> str:
    """Strip AT&T's % sigil and MIPS' $ sigil, lowercase."""
    return token.strip().lstrip('%$').lower()


def lookup(token: str, arch: str = 'x86'):
    """Return (role, width, parent) for a register token, or None."""
    table = ARCH_REGISTERS.get(arch, _X86)
    return table.get(normalise(token))


def is_register(token: str, arch: str = 'x86') -> bool:
    return lookup(token, arch) is not None


def describe(token: str, arch: str = 'x86') -> str:
    """Human phrase for a register, e.g. 'ECX (counter)'."""
    info = lookup(token, arch)
    name = normalise(token).upper()
    if not info:
        return name
    # Roles carry a parenthetical aside; drop it so phrases don't nest brackets.
    role = info[0].split(' (')[0]
    return f'{name} ({role})'


def width_of(token: str, arch: str = 'x86'):
    info = lookup(token, arch)
    return info[1] if info else None
