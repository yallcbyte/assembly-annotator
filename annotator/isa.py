"""Instruction knowledge base.

Each entry carries:
  name      - the mnemonic spelled out
  category  - drives colour coding in the UI
  summary   - generic one-liner (operand-free fallback)
  template  - operand-aware sentence; {dst}/{src}/{op0}.. are filled by explain.py
  flags     - CPU flags the instruction writes, '' if none
  detail    - a teaching note shown when a line is expanded
"""

CATEGORIES = {
    'data':    {'label': 'Data movement',   'colour': '#4fc3f7'},
    'arith':   {'label': 'Arithmetic',      'colour': '#81c784'},
    'logic':   {'label': 'Bitwise / logic', 'colour': '#ba68c8'},
    'stack':   {'label': 'Stack',           'colour': '#ffb74d'},
    'control': {'label': 'Control flow',    'colour': '#e57373'},
    'compare': {'label': 'Comparison',      'colour': '#f06292'},
    'string':  {'label': 'String / memory', 'colour': '#4db6ac'},
    'system':  {'label': 'System',          'colour': '#ff8a65'},
    'simd':    {'label': 'SIMD / float',    'colour': '#9fa8da'},
    'flags':   {'label': 'Flag handling',   'colour': '#fff176'},
    'other':   {'label': 'Other',           'colour': '#90a4ae'},
}

# Condition suffixes shared by jcc / setcc / cmovcc.
CONDITIONS = {
    'e':   'equal (ZF=1)',            'z':   'zero (ZF=1)',
    'ne':  'not equal (ZF=0)',        'nz':  'not zero (ZF=0)',
    'g':   'greater, signed',         'nle': 'greater, signed',
    'ge':  'greater or equal, signed','nl':  'greater or equal, signed',
    'l':   'less, signed',            'nge': 'less, signed',
    'le':  'less or equal, signed',   'ng':  'less or equal, signed',
    'a':   'above, unsigned',         'nbe': 'above, unsigned',
    'ae':  'above or equal, unsigned','nb':  'above or equal, unsigned',
    'b':   'below, unsigned',         'nae': 'below, unsigned',
    'be':  'below or equal, unsigned','na':  'below or equal, unsigned',
    's':   'sign flag set (negative)','ns':  'sign flag clear (non-negative)',
    'o':   'overflow',                'no':  'no overflow',
    'c':   'carry set',               'nc':  'carry clear',
    'p':   'parity even',             'pe':  'parity even',
    'np':  'parity odd',              'po':  'parity odd',
    'cxz': 'CX is zero',              'ecxz':'ECX is zero',
    'rcxz':'RCX is zero',
}


def _i(name, category, summary, template='', flags='', detail=''):
    return {'name': name, 'category': category, 'summary': summary,
            'template': template, 'flags': flags, 'detail': detail}


X86 = {
    # ---- data movement -------------------------------------------------
    'mov':    _i('Move', 'data', 'Copy the source value into the destination',
                 'Set {dst} to {src}', '',
                 'MOV never touches the flags, which is why XOR is preferred for zeroing when flags are free.'),
    'movabs': _i('Move absolute', 'data', 'Load a full 64-bit immediate into a register',
                 'Load the 64-bit constant {src} into {dst}'),
    'movzx':  _i('Move with zero-extend', 'data', 'Copy a smaller value and pad the top with zeros',
                 'Copy {src} into {dst}, zero-filling the upper bits', '',
                 'Used when widening unsigned values; the high bits are cleared rather than sign-copied.'),
    'movsx':  _i('Move with sign-extend', 'data', 'Copy a smaller value and replicate its sign bit',
                 'Copy {src} into {dst}, sign-extending to the wider size'),
    'movsxd': _i('Move sign-extend dword', 'data', 'Copy a 32-bit value into 64 bits, preserving sign',
                 'Copy {src} into {dst}, sign-extending 32 bits to 64'),
    'lea':    _i('Load effective address', 'data', 'Compute an address without reading memory',
                 'Compute the address {src} and put it in {dst}', '',
                 'LEA is often used as a fast arithmetic trick: `lea eax, [ebx+ecx*4]` is a multiply-add with no memory access.'),
    'xchg':   _i('Exchange', 'data', 'Swap the two operands',
                 'Swap the contents of {dst} and {src}'),
    'cmov':   _i('Conditional move', 'data', 'Copy only if a condition holds',
                 'Copy {src} into {dst}, but only if the condition holds'),
    'bswap':  _i('Byte swap', 'data', 'Reverse byte order (endianness flip)',
                 'Reverse the byte order of {dst}'),
    'cdq':    _i('Convert dword to qword', 'data', 'Sign-extend EAX into EDX:EAX',
                 'Sign-extend EAX into EDX:EAX (sets up a signed division)'),
    'cqo':    _i('Convert qword to oword', 'data', 'Sign-extend RAX into RDX:RAX',
                 'Sign-extend RAX into RDX:RAX (sets up a signed division)'),
    'cwd':    _i('Convert word to dword', 'data', 'Sign-extend AX into DX:AX',
                 'Sign-extend AX into DX:AX'),
    'cbw':    _i('Convert byte to word', 'data', 'Sign-extend AL into AX', 'Sign-extend AL into AX'),
    'cdqe':   _i('Convert dword to qword (RAX)', 'data', 'Sign-extend EAX into RAX', 'Sign-extend EAX into RAX'),

    # ---- arithmetic ----------------------------------------------------
    'add':    _i('Add', 'arith', 'Add the source to the destination',
                 'Add {src} to {dst}', 'OF SF ZF AF CF PF'),
    'adc':    _i('Add with carry', 'arith', 'Add the source plus the carry flag',
                 'Add {src} plus the carry flag to {dst}', 'OF SF ZF AF CF PF',
                 'Used to chain additions across registers for numbers wider than the machine word.'),
    'sub':    _i('Subtract', 'arith', 'Subtract the source from the destination',
                 'Subtract {src} from {dst}', 'OF SF ZF AF CF PF'),
    'sbb':    _i('Subtract with borrow', 'arith', 'Subtract the source and the carry flag',
                 'Subtract {src} and the borrow from {dst}', 'OF SF ZF AF CF PF'),
    'inc':    _i('Increment', 'arith', 'Add one', 'Add 1 to {dst}', 'OF SF ZF AF PF'),
    'dec':    _i('Decrement', 'arith', 'Subtract one', 'Subtract 1 from {dst}', 'OF SF ZF AF PF'),
    'neg':    _i('Negate', 'arith', 'Replace the operand with its two’s-complement negation',
                 'Negate {dst} (replace it with 0 - {dst})', 'OF SF ZF AF CF PF'),
    'mul':    _i('Unsigned multiply', 'arith', 'Multiply the accumulator by the operand, unsigned',
                 'Multiply the accumulator by {op0}, unsigned, result in EDX:EAX', 'OF CF'),
    'imul':   _i('Signed multiply', 'arith', 'Multiply, treating the operands as signed',
                 'Multiply {dst} by {src}, signed', 'OF CF'),
    'div':    _i('Unsigned divide', 'arith', 'Divide EDX:EAX by the operand, unsigned',
                 'Divide EDX:EAX by {op0}, unsigned (quotient in EAX, remainder in EDX)', '',
                 'A zero divisor or an oversized quotient raises a divide-error exception.'),
    'idiv':   _i('Signed divide', 'arith', 'Divide EDX:EAX by the operand, signed',
                 'Divide EDX:EAX by {op0}, signed (quotient in EAX, remainder in EDX)'),

    # ---- bitwise / logic ----------------------------------------------
    'and':    _i('Bitwise AND', 'logic', 'Keep only the bits set in both operands',
                 'Bitwise-AND {dst} with {src}', 'SF ZF PF (OF=CF=0)',
                 'Masking idiom: `and eax, 0xFF` keeps the lowest byte and clears the rest.'),
    'or':     _i('Bitwise OR', 'logic', 'Set every bit that is set in either operand',
                 'Bitwise-OR {dst} with {src}', 'SF ZF PF (OF=CF=0)'),
    'xor':    _i('Bitwise XOR', 'logic', 'Set the bits that differ between the operands',
                 'Bitwise-XOR {dst} with {src}', 'SF ZF PF (OF=CF=0)',
                 '`xor reg, reg` is the standard two-byte way to zero a register.'),
    'not':    _i('Bitwise NOT', 'logic', 'Flip every bit', 'Invert every bit of {dst}'),
    'shl':    _i('Shift left', 'logic', 'Shift bits left, filling with zeros',
                 'Shift {dst} left by {src} bits (multiply by 2^{src})', 'CF OF SF ZF PF'),
    'sal':    _i('Shift arithmetic left', 'logic', 'Shift bits left, filling with zeros',
                 'Shift {dst} left by {src} bits', 'CF OF SF ZF PF'),
    'shr':    _i('Shift right (logical)', 'logic', 'Shift bits right, filling with zeros',
                 'Shift {dst} right by {src} bits, unsigned (divide by 2^{src})', 'CF OF SF ZF PF'),
    'sar':    _i('Shift right (arithmetic)', 'logic', 'Shift bits right, copying the sign bit',
                 'Shift {dst} right by {src} bits, keeping the sign', 'CF OF SF ZF PF'),
    'rol':    _i('Rotate left', 'logic', 'Rotate bits left, wrapping around',
                 'Rotate {dst} left by {src} bits', 'CF OF'),
    'ror':    _i('Rotate right', 'logic', 'Rotate bits right, wrapping around',
                 'Rotate {dst} right by {src} bits', 'CF OF'),
    'rcl':    _i('Rotate left through carry', 'logic', 'Rotate left including the carry flag',
                 'Rotate {dst} left by {src} bits through the carry flag', 'CF OF'),
    'rcr':    _i('Rotate right through carry', 'logic', 'Rotate right including the carry flag',
                 'Rotate {dst} right by {src} bits through the carry flag', 'CF OF'),
    'bt':     _i('Bit test', 'logic', 'Copy one bit into the carry flag',
                 'Copy bit {src} of {dst} into the carry flag', 'CF'),
    'bts':    _i('Bit test and set', 'logic', 'Test a bit, then set it',
                 'Test bit {src} of {dst}, then set it', 'CF'),
    'btr':    _i('Bit test and reset', 'logic', 'Test a bit, then clear it',
                 'Test bit {src} of {dst}, then clear it', 'CF'),
    'bsf':    _i('Bit scan forward', 'logic', 'Find the lowest set bit',
                 'Find the lowest set bit of {src} and store its index in {dst}', 'ZF'),
    'bsr':    _i('Bit scan reverse', 'logic', 'Find the highest set bit',
                 'Find the highest set bit of {src} and store its index in {dst}', 'ZF'),
    'popcnt': _i('Population count', 'logic', 'Count the set bits',
                 'Count the 1-bits in {src} and store the total in {dst}', 'ZF'),

    # ---- comparison ----------------------------------------------------
    'cmp':    _i('Compare', 'compare', 'Subtract the operands and set flags, discarding the result',
                 'Compare {dst} with {src} (sets flags; nothing is stored)', 'OF SF ZF AF CF PF',
                 'CMP is a SUB that throws away the answer. The conditional jump that follows reads the flags it left behind.'),
    'test':   _i('Test', 'compare', 'Bitwise-AND the operands and set flags, discarding the result',
                 'Test {dst} against {src} (sets flags; nothing is stored)', 'SF ZF PF (OF=CF=0)',
                 '`test reg, reg` is the idiomatic null/zero check — cheaper than `cmp reg, 0`.'),

    # ---- stack ---------------------------------------------------------
    'push':   _i('Push', 'stack', 'Put a value on the stack',
                 'Push {op0} onto the stack (the stack pointer drops)'),
    'pop':    _i('Pop', 'stack', 'Take the top value off the stack',
                 'Pop the top of the stack into {op0} (the stack pointer rises)'),
    'pusha':  _i('Push all', 'stack', 'Push all general-purpose registers', 'Push every general-purpose register'),
    'popa':   _i('Pop all', 'stack', 'Restore all general-purpose registers', 'Restore every general-purpose register'),
    'pushf':  _i('Push flags', 'stack', 'Push the flags register', 'Push the flags register onto the stack'),
    'popf':   _i('Pop flags', 'stack', 'Restore the flags register', 'Restore the flags register from the stack', 'all'),
    'enter':  _i('Enter frame', 'stack', 'Build a stack frame', 'Set up a stack frame reserving {op0} bytes'),
    'leave':  _i('Leave frame', 'stack', 'Tear down the stack frame',
                 'Tear down the stack frame (equivalent to `mov esp, ebp` then `pop ebp`)'),

    # ---- control flow --------------------------------------------------
    'jmp':    _i('Jump', 'control', 'Jump unconditionally', 'Jump to {op0} — always taken'),
    'call':   _i('Call', 'control', 'Call a procedure',
                 'Call {op0}, pushing the return address onto the stack'),
    'ret':    _i('Return', 'control', 'Return to the caller',
                 'Return to the caller (pops the saved return address)'),
    'retn':   _i('Return near', 'control', 'Return to the caller', 'Return to the caller'),
    'iret':   _i('Interrupt return', 'control', 'Return from an interrupt handler', 'Return from an interrupt handler'),
    'loop':   _i('Loop', 'control', 'Decrement ECX and jump while it is non-zero',
                 'Decrement ECX and jump back to {op0} unless ECX hit zero', '',
                 'A one-instruction countdown loop. The counter is always ECX/RCX — it is not an operand.'),
    'loope':  _i('Loop while equal', 'control', 'Loop while ECX is non-zero and ZF is set',
                 'Decrement ECX and jump to {op0} while ECX is non-zero and the zero flag is set'),
    'loopne': _i('Loop while not equal', 'control', 'Loop while ECX is non-zero and ZF is clear',
                 'Decrement ECX and jump to {op0} while ECX is non-zero and the zero flag is clear'),

    # ---- flags ---------------------------------------------------------
    'clc':    _i('Clear carry', 'flags', 'Clear the carry flag', 'Clear the carry flag', 'CF=0'),
    'stc':    _i('Set carry', 'flags', 'Set the carry flag', 'Set the carry flag', 'CF=1'),
    'cld':    _i('Clear direction', 'flags', 'Clear the direction flag (string ops count up)',
                 'Clear the direction flag so string operations move forward', 'DF=0'),
    'std':    _i('Set direction', 'flags', 'Set the direction flag (string ops count down)',
                 'Set the direction flag so string operations move backward', 'DF=1'),
    'cli':    _i('Clear interrupt flag', 'flags', 'Disable maskable interrupts', 'Disable maskable interrupts', 'IF=0'),
    'sti':    _i('Set interrupt flag', 'flags', 'Enable maskable interrupts', 'Enable maskable interrupts', 'IF=1'),
    'cmc':    _i('Complement carry', 'flags', 'Flip the carry flag', 'Flip the carry flag', 'CF'),
    'lahf':   _i('Load AH from flags', 'flags', 'Copy the low flags byte into AH', 'Copy the low flags byte into AH'),
    'sahf':   _i('Store AH to flags', 'flags', 'Copy AH into the low flags byte', 'Copy AH into the low flags byte', 'SF ZF AF PF CF'),

    # ---- string / memory ----------------------------------------------
    'movs':   _i('Move string', 'string', 'Copy from [ESI] to [EDI]', 'Copy one element from [ESI] to [EDI] and advance both'),
    'movsb':  _i('Move string byte', 'string', 'Copy a byte from [ESI] to [EDI]', 'Copy one byte from [ESI] to [EDI] and advance both'),
    'movsw':  _i('Move string word', 'string', 'Copy a word from [ESI] to [EDI]', 'Copy one word from [ESI] to [EDI] and advance both'),
    'movsd':  _i('Move string dword', 'string', 'Copy a dword from [ESI] to [EDI]', 'Copy one dword from [ESI] to [EDI] and advance both'),
    'stos':   _i('Store string', 'string', 'Write the accumulator to [EDI]', 'Write the accumulator to [EDI] and advance'),
    'stosb':  _i('Store string byte', 'string', 'Write AL to [EDI]', 'Write AL to [EDI] and advance EDI'),
    'stosd':  _i('Store string dword', 'string', 'Write EAX to [EDI]', 'Write EAX to [EDI] and advance EDI'),
    'lods':   _i('Load string', 'string', 'Read [ESI] into the accumulator', 'Load from [ESI] into the accumulator and advance'),
    'lodsb':  _i('Load string byte', 'string', 'Read a byte from [ESI] into AL', 'Load a byte from [ESI] into AL and advance ESI'),
    'scas':   _i('Scan string', 'string', 'Compare the accumulator with [EDI]', 'Compare the accumulator with [EDI] and advance'),
    'scasb':  _i('Scan string byte', 'string', 'Compare AL with [EDI]', 'Compare AL with [EDI] and advance EDI', 'OF SF ZF AF CF PF'),
    'cmps':   _i('Compare strings', 'string', 'Compare [ESI] with [EDI]', 'Compare [ESI] with [EDI] and advance both', 'OF SF ZF AF CF PF'),
    'cmpsb':  _i('Compare string bytes', 'string', 'Compare a byte at [ESI] with [EDI]', 'Compare the bytes at [ESI] and [EDI], then advance both', 'OF SF ZF AF CF PF'),
    'rep':    _i('Repeat prefix', 'string', 'Repeat the following string op ECX times',
                 'Repeat the following instruction until ECX reaches zero'),
    'repe':   _i('Repeat while equal', 'string', 'Repeat while ZF is set and ECX is non-zero',
                 'Repeat the following instruction while the values match'),
    'repne':  _i('Repeat while not equal', 'string', 'Repeat while ZF is clear and ECX is non-zero',
                 'Repeat the following instruction while the values differ'),

    # ---- system --------------------------------------------------------
    'int':    _i('Interrupt', 'system', 'Raise a software interrupt',
                 'Raise software interrupt {op0}'),
    'int3':   _i('Breakpoint', 'system', 'Trigger a debugger breakpoint',
                 'Breakpoint trap — hands control to an attached debugger', '',
                 'A lone 0xCC byte. Debuggers patch it in; packers scan for it to detect tampering.'),
    'syscall':_i('System call', 'system', 'Enter the kernel (64-bit)',
                 'Enter the kernel to run the system call selected by RAX'),
    'sysenter':_i('Fast system call', 'system', 'Enter the kernel (fast path)', 'Enter the kernel via the fast system-call path'),
    'endbr64': _i('End branch 64', 'system', 'Marks a legal indirect-branch target',
                  'Mark this as a valid landing spot for an indirect jump or call', '',
                  'Part of Intel CET. The CPU faults if an indirect branch lands anywhere '
                  'else, which breaks ROP and JOP gadget chains. Ubiquitous in modern code.'),
    'endbr32': _i('End branch 32', 'system', 'Marks a legal indirect-branch target',
                  'Mark this as a valid landing spot for an indirect jump or call'),
    'pause':  _i('Spin-loop hint', 'system', 'Hint that this is a spin-wait loop',
                 'Hint to the CPU that this is a spin-wait loop'),
    'nop':    _i('No operation', 'other', 'Do nothing for one instruction',
                 'Do nothing — a one-instruction pause', '',
                 'Used for alignment padding, patching out code, and as the landing zone of a NOP sled.'),
    'hlt':    _i('Halt', 'system', 'Stop the processor until the next interrupt', 'Halt the processor until an interrupt arrives'),
    'ud2':    _i('Undefined instruction', 'system', 'Raise an invalid-opcode exception', 'Deliberately raise an invalid-opcode exception'),
    'cpuid':  _i('CPU identification', 'system', 'Query processor features',
                 'Query processor identity and feature bits (selected by EAX)', '',
                 'Also a common VM-detection probe: hypervisors leave fingerprints in the leaf results.'),
    'rdtsc':  _i('Read timestamp counter', 'system', 'Read the cycle counter into EDX:EAX',
                 'Read the CPU cycle counter into EDX:EAX', '',
                 'Timing checks built on RDTSC are a classic anti-debugging trick.'),
    'in':     _i('Port input', 'system', 'Read from an I/O port', 'Read from I/O port {src} into {dst}'),
    'out':    _i('Port output', 'system', 'Write to an I/O port', 'Write {src} to I/O port {dst}'),
    'lock':   _i('Lock prefix', 'system', 'Make the next memory operation atomic',
                 'Make the following memory operation atomic across cores'),
    'xadd':   _i('Exchange and add', 'arith', 'Swap operands then add', 'Swap {dst} and {src}, then store their sum in {dst}', 'OF SF ZF AF CF PF'),
    'cmpxchg':_i('Compare and exchange', 'system', 'Atomic compare-and-swap',
                 'Compare the accumulator with {dst}; swap in {src} if they match', 'ZF'),

    # ---- SIMD / float (common ones) ------------------------------------
    'movss':  _i('Move scalar single', 'simd', 'Move a 32-bit float', 'Move the single-precision float {src} into {dst}'),
    'movaps': _i('Move aligned packed single', 'simd', 'Move 128 bits, aligned', 'Move 128 aligned bits from {src} into {dst}'),
    'movups': _i('Move unaligned packed single', 'simd', 'Move 128 bits, unaligned', 'Move 128 unaligned bits from {src} into {dst}'),
    'movdqa': _i('Move aligned dqword', 'simd', 'Move 128 integer bits, aligned', 'Move 128 aligned integer bits from {src} into {dst}'),
    'movdqu': _i('Move unaligned dqword', 'simd', 'Move 128 integer bits, unaligned', 'Move 128 unaligned integer bits from {src} into {dst}'),
    'addps':  _i('Add packed single', 'simd', 'Add four floats in parallel', 'Add the four packed floats of {src} to {dst}'),
    'mulps':  _i('Multiply packed single', 'simd', 'Multiply four floats in parallel', 'Multiply the four packed floats of {dst} by {src}'),
    'pxor':   _i('Packed XOR', 'simd', 'Bitwise XOR of 128-bit registers', 'Bitwise-XOR {dst} with {src}'),
    'fld':    _i('Float load', 'simd', 'Push a float onto the x87 stack', 'Push {op0} onto the x87 floating-point stack'),
    'fstp':   _i('Float store and pop', 'simd', 'Pop the x87 stack into memory', 'Pop the top of the x87 stack into {op0}'),
    'fadd':   _i('Float add', 'simd', 'Add on the x87 stack', 'Add {op0} on the x87 floating-point stack'),
}

# jcc / setcc / cmovcc are generated rather than listed one by one.
for _cc, _meaning in CONDITIONS.items():
    X86.setdefault(f'j{_cc}', _i(
        f'Jump if {_meaning}', 'control',
        f'Jump when the previous comparison was {_meaning}',
        'Jump to {op0} if the last comparison was ' + _meaning,
        '', 'Conditional jumps read the flags left by the nearest preceding CMP, TEST or arithmetic instruction.'))
    X86.setdefault(f'set{_cc}', _i(
        f'Set if {_meaning}', 'compare',
        f'Write 1 when the comparison was {_meaning}, else 0',
        'Set {op0} to 1 if the last comparison was ' + _meaning + ', otherwise 0'))
    X86.setdefault(f'cmov{_cc}', _i(
        f'Conditional move if {_meaning}', 'data',
        f'Copy only when the comparison was {_meaning}',
        'Copy {src} into {dst} only if the last comparison was ' + _meaning,
        '', 'Branch-free selection — avoids a mispredictable jump.'))

ARM = {
    'mov':  _i('Move', 'data', 'Copy a value into a register', 'Set {dst} to {src}'),
    'movz': _i('Move with zero', 'data', 'Load an immediate, zeroing the rest', 'Set {dst} to {src}, zeroing the other bits'),
    'movk': _i('Move keeping', 'data', 'Patch 16 bits of a register', 'Insert {src} into {dst}, keeping the other bits'),
    'ldr':  _i('Load register', 'data', 'Read a value from memory', 'Load {dst} from memory at {src}'),
    'ldp':  _i('Load pair', 'data', 'Load two registers at once', 'Load {op0} and {op1} from memory at {op2}'),
    'str':  _i('Store register', 'data', 'Write a value to memory', 'Store {dst} into memory at {src}'),
    'stp':  _i('Store pair', 'stack', 'Store two registers at once', 'Store {op0} and {op1} to memory at {op2}',
               '', 'An AArch64 prologue usually opens with `stp x29, x30, [sp, #-N]!` — saving the frame pointer and return address.'),
    'add':  _i('Add', 'arith', 'Add two values', 'Set {dst} to {src} plus the remaining operand'),
    'sub':  _i('Subtract', 'arith', 'Subtract two values', 'Set {dst} to {src} minus the remaining operand'),
    'mul':  _i('Multiply', 'arith', 'Multiply two values', 'Set {dst} to the product of the source operands'),
    'sdiv': _i('Signed divide', 'arith', 'Divide, signed', 'Set {dst} to the signed quotient of the source operands'),
    'cmp':  _i('Compare', 'compare', 'Compare and set condition flags', 'Compare {dst} with {src} and set the condition flags', 'NZCV'),
    'cmn':  _i('Compare negative', 'compare', 'Compare against the negation', 'Compare {dst} with the negation of {src}', 'NZCV'),
    'tst':  _i('Test bits', 'compare', 'Bitwise-AND and set flags', 'Test {dst} against {src} and set the condition flags', 'NZCV'),
    'and':  _i('Bitwise AND', 'logic', 'Bitwise AND', 'Bitwise-AND the source operands into {dst}'),
    'orr':  _i('Bitwise OR', 'logic', 'Bitwise OR', 'Bitwise-OR the source operands into {dst}'),
    'eor':  _i('Bitwise XOR', 'logic', 'Bitwise exclusive OR', 'Bitwise-XOR the source operands into {dst}'),
    'lsl':  _i('Logical shift left', 'logic', 'Shift left', 'Shift {src} left and store the result in {dst}'),
    'lsr':  _i('Logical shift right', 'logic', 'Shift right', 'Shift {src} right and store the result in {dst}'),
    'b':    _i('Branch', 'control', 'Jump unconditionally', 'Branch to {op0} — always taken'),
    'bl':   _i('Branch with link', 'control', 'Call a function', 'Call {op0}, saving the return address in LR'),
    'blr':  _i('Branch with link to register', 'control', 'Call through a register', 'Call the address held in {op0}, saving the return address in LR'),
    'br':   _i('Branch to register', 'control', 'Jump through a register', 'Jump to the address held in {op0}'),
    'ret':  _i('Return', 'control', 'Return to the caller', 'Return to the address in the link register'),
    'cbz':  _i('Compare and branch if zero', 'control', 'Branch when the register is zero', 'Branch to {src} if {dst} is zero'),
    'cbnz': _i('Compare and branch if non-zero', 'control', 'Branch when the register is non-zero', 'Branch to {src} if {dst} is not zero'),
    'svc':  _i('Supervisor call', 'system', 'Enter the kernel', 'Enter the kernel — the system call number is in X8'),
    'nop':  _i('No operation', 'other', 'Do nothing', 'Do nothing — a one-instruction pause'),
    'push': _i('Push', 'stack', 'Push registers onto the stack', 'Push {op0} onto the stack'),
    'pop':  _i('Pop', 'stack', 'Pop registers from the stack', 'Pop {op0} from the stack'),
    'adr':  _i('Address of', 'data', 'Load a PC-relative address', 'Load the address of {src} into {dst}'),
    'adrp': _i('Address of page', 'data', 'Load the 4 KB page address of a symbol',
               'Load the page address of {src} into {dst}', '',
               'AArch64 builds addresses in two steps: ADRP for the page, then an ADD or LDR for the offset.'),
    'ldrb': _i('Load byte', 'data', 'Read one byte from memory', 'Load one byte from {src} into {dst}'),
    'ldrh': _i('Load halfword', 'data', 'Read 16 bits from memory', 'Load 16 bits from {src} into {dst}'),
    'strb': _i('Store byte', 'data', 'Write one byte to memory', 'Store the low byte of {dst} into {src}'),
    'strh': _i('Store halfword', 'data', 'Write 16 bits to memory', 'Store the low 16 bits of {dst} into {src}'),
    'ldur': _i('Load unscaled', 'data', 'Read memory at an unscaled offset', 'Load {dst} from memory at {src}'),
    'stur': _i('Store unscaled', 'data', 'Write memory at an unscaled offset', 'Store {dst} into memory at {src}'),
    'neg':  _i('Negate', 'arith', 'Negate a value', 'Set {dst} to the negation of {src}'),
    'mvn':  _i('Bitwise NOT', 'logic', 'Invert every bit', 'Set {dst} to the bitwise inverse of {src}'),
    'udiv': _i('Unsigned divide', 'arith', 'Divide, unsigned', 'Set {dst} to the unsigned quotient of the source operands'),
    'madd': _i('Multiply-add', 'arith', 'Multiply then add', 'Multiply two operands, add the third, and store the result in {dst}'),
    'msub': _i('Multiply-subtract', 'arith', 'Multiply then subtract', 'Multiply two operands, subtract that from the third, and store the result in {dst}'),
    'csel': _i('Conditional select', 'data', 'Pick one of two registers on a condition',
               'Set {dst} to one of the source registers depending on the condition flags'),
    'cset': _i('Conditional set', 'compare', 'Set a register to 0 or 1 on a condition',
               'Set {dst} to 1 if the condition holds, otherwise 0'),
    'sxtw': _i('Sign-extend word', 'data', 'Widen 32 bits to 64, keeping the sign', 'Sign-extend {src} into {dst}'),
    'uxtb': _i('Zero-extend byte', 'data', 'Widen a byte, padding with zeros', 'Zero-extend the low byte of {src} into {dst}'),
    'asr':  _i('Arithmetic shift right', 'logic', 'Shift right, keeping the sign', 'Shift {src} right, preserving its sign, into {dst}'),
    'bic':  _i('Bit clear', 'logic', 'AND with the complement', 'Clear the bits of {dst} that are set in the source operand'),
    'dmb':  _i('Data memory barrier', 'system', 'Order memory accesses', 'Wait until earlier memory accesses are visible'),
    'brk':  _i('Breakpoint', 'system', 'Trigger a debugger trap', 'Breakpoint trap — hands control to a debugger'),
}
for _cc in ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'hi', 'ls', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc']:
    ARM.setdefault(f'b.{_cc}', _i(f'Branch if {_cc}', 'control',
                                  f'Branch when the condition {_cc} holds',
                                  'Branch to {op0} if the condition ' + _cc + ' holds'))

MIPS = {
    'lw':   _i('Load word', 'data', 'Read a word from memory', 'Load {dst} from memory at {src}'),
    'sw':   _i('Store word', 'data', 'Write a word to memory', 'Store {dst} into memory at {src}'),
    'li':   _i('Load immediate', 'data', 'Load a constant', 'Set {dst} to {src}'),
    'la':   _i('Load address', 'data', 'Load an address', 'Load the address of {src} into {dst}'),
    'move': _i('Move', 'data', 'Copy a register', 'Copy {src} into {dst}'),
    'add':  _i('Add', 'arith', 'Add two registers', 'Set {dst} to the sum of the source operands'),
    'addi': _i('Add immediate', 'arith', 'Add a constant', 'Set {dst} to {src} plus the immediate'),
    'sub':  _i('Subtract', 'arith', 'Subtract two registers', 'Set {dst} to the difference of the source operands'),
    'mult': _i('Multiply', 'arith', 'Multiply two registers', 'Multiply the operands into HI:LO'),
    'beq':  _i('Branch if equal', 'control', 'Branch when two registers match', 'Branch to {op2} if {op0} equals {op1}'),
    'bne':  _i('Branch if not equal', 'control', 'Branch when two registers differ', 'Branch to {op2} if {op0} differs from {op1}'),
    'j':    _i('Jump', 'control', 'Jump unconditionally', 'Jump to {op0}'),
    'jal':  _i('Jump and link', 'control', 'Call a function', 'Call {op0}, saving the return address in $ra'),
    'jr':   _i('Jump register', 'control', 'Jump through a register', 'Jump to the address in {op0}'),
    'nop':  _i('No operation', 'other', 'Do nothing', 'Do nothing — a one-instruction pause'),
    'syscall': _i('System call', 'system', 'Enter the kernel', 'Enter the kernel — the call number is in $v0'),
}

ARCH_TABLES = {'x86': X86, 'arm': ARM, 'mips': MIPS}


def lookup(mnemonic: str, arch: str = 'x86'):
    """Find an instruction entry, tolerating operand-size suffixes."""
    table = ARCH_TABLES.get(arch, X86)
    m = mnemonic.lower()
    if m in table:
        return table[m]
    # AT&T appends a size suffix: movl, addq, cmpb ... try the bare mnemonic.
    if arch == 'x86' and len(m) > 2 and m[-1] in 'bwlq':
        base = m[:-1]
        if base in table:
            return table[base]
    return None


def canonical(mnemonic: str, arch: str = 'x86') -> str:
    """The mnemonic with any AT&T size suffix removed, if that resolves."""
    m = (mnemonic or '').lower()
    table = ARCH_TABLES.get(arch, X86)
    if m in table:
        return m
    if arch == 'x86' and len(m) > 2 and m[-1] in 'bwlq' and m[:-1] in table:
        return m[:-1]
    return m


def category_of(mnemonic: str, arch: str = 'x86') -> str:
    entry = lookup(mnemonic, arch)
    return entry['category'] if entry else 'other'
