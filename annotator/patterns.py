"""Pattern detection.

Every pattern carries a plain-English description, a severity and the exact
line numbers that triggered it, so the UI can explain *why* a chip lit up and
jump the reader to the evidence.
"""

import re
from typing import Callable, List, Optional

from . import isa

SEVERITIES = ('info', 'notable', 'warning')


class Pattern:
    def __init__(self, pid, name, description, severity='info', category='structure',
                 sequence=None, all_of=None, any_of=None, regex=None, custom=None,
                 window=6, min_count=1):
        self.id = pid
        self.name = name
        self.description = description
        self.severity = severity
        self.category = category
        self.sequence = [s.lower() for s in sequence] if sequence else None
        self.all_of = [s.lower() for s in all_of] if all_of else None
        self.any_of = [s.lower() for s in any_of] if any_of else None
        self.regex = re.compile(regex, re.IGNORECASE) if regex else None
        self.custom: Optional[Callable] = custom
        self.window = window
        self.min_count = min_count

    def match(self, ctx) -> List[int]:
        """Return the 1-based line numbers that triggered this pattern."""
        if self.custom:
            return self.custom(ctx)
        if self.sequence:
            return self._match_sequence(ctx)
        if self.all_of:
            hits = []
            for needle in self.all_of:
                found = ctx.find(needle)
                if not found:
                    return []
                hits.extend(found)
            return sorted(set(hits))
        if self.any_of:
            hits = []
            for needle in self.any_of:
                hits.extend(ctx.find(needle))
            return sorted(set(hits)) if len(hits) >= self.min_count else []
        if self.regex:
            return [ln.index for ln in ctx.instructions
                    if self.regex.search(ctx.normal_text(ln))]
        return []

    def _match_sequence(self, ctx) -> List[int]:
        """Ordered match within a sliding window, gaps allowed."""
        instrs = ctx.instructions
        for start in range(len(instrs)):
            pos, matched = start, []
            for needle in self.sequence:
                while pos < len(instrs) and pos - start < self.window:
                    if ctx.normal_text(instrs[pos]).startswith(needle):
                        matched.append(instrs[pos].index)
                        pos += 1
                        break
                    pos += 1
                else:
                    break
            if len(matched) == len(self.sequence):
                return matched
        return []


class MatchContext:
    """Pre-chewed view of the listing that patterns query."""

    def __init__(self, lines, meta, cfg=None):
        self.lines = lines
        self.meta = meta
        self.cfg = cfg or {}
        self.arch = meta.get('arch', 'x86')
        self.instructions = [l for l in lines if l.kind == 'instruction']
        self._text = {l.index: self._normalise(l) for l in self.instructions}

    def _normalise(self, line) -> str:
        # Patterns are written in Intel spelling, so drop AT&T's % and $ sigils
        # and MIPS' $ -- otherwise `push %rbp` would never match `push rbp`.
        parts = []
        for o in line.operands:
            parts.append(o.register if o.kind == 'register' else o.text.lower().lstrip('$'))
        mnemonic = isa.canonical(line.mnemonic, self.arch)
        return f'{mnemonic} {", ".join(parts)}'.strip()

    def normal_text(self, line) -> str:
        return self._text.get(line.index, '')

    def find(self, needle: str) -> List[int]:
        needle = needle.lower()
        return [i for i, t in self._text.items()
                if t == needle or t.startswith(needle + ' ') or t.split(' ')[0] == needle]

    def mnemonics(self) -> List[str]:
        return [l.mnemonic for l in self.instructions]


# ---- custom matchers --------------------------------------------------

def _nop_sled(ctx):
    run, best = [], []
    for l in ctx.instructions:
        if l.mnemonic == 'nop':
            run.append(l.index)
            if len(run) > len(best):
                best = list(run)
        else:
            run = []
    return best if len(best) >= 3 else []


def _repeated_push(ctx):
    run, best = [], []
    for l in ctx.instructions:
        if l.mnemonic == 'push':
            run.append(l.index)
            if len(run) > len(best):
                best = list(run)
        else:
            run = []
    return best if len(best) >= 3 else []


def _hardcoded_constants(ctx):
    hits = []
    for l in ctx.instructions:
        for op in l.operands:
            if op.kind == 'immediate' and op.value is not None and op.value > 0xFF:
                hits.append(l.index)
                break
    return hits


def _self_modifying(ctx):
    """Stores aimed at an address this listing also executes.

    RIP-relative addressing is NOT a signal here: `mov [rip+0x2efd], 1` is the
    ordinary way 64-bit code reaches a global, and treating it as tampering
    flags almost every modern binary. We look instead for a store whose target
    names a label that is branched to, i.e. code being overwritten.
    """
    labels = {n.lower() for n in ctx.cfg.get('labels', {})}
    branched_to = {e.get('target', '').lower()
                   for e in ctx.cfg.get('edges', []) if e.get('target')}
    executed = labels & branched_to
    if not executed:
        return []
    hits = []
    for l in ctx.instructions:
        if l.mnemonic not in ('mov', 'stosb', 'stosd', 'stosw', 'xor', 'add', 'sub', 'or'):
            continue
        if not l.operands or l.operands[0].kind != 'memory':
            continue
        # Split the operand into identifier tokens instead of substring
        # matching, so a label `go` does not match `[ebp+goto_table]`.
        tokens = set(re.split('[^0-9A-Za-z_.$@]+', l.operands[0].text.lower()))
        if tokens & executed:
            hits.append(l.index)
    return hits


def _stack_strings(ctx):
    """Characters pushed one at a time -- strings assembled on the stack."""
    hits = []
    for l in ctx.instructions:
        if l.mnemonic in ('push', 'mov') and l.operands:
            last = l.operands[-1]
            if last.kind == 'immediate' and last.value is not None:
                v = last.value
                if v and all(0x20 <= (v >> s) & 0xFF <= 0x7E
                             for s in range(0, max(8, v.bit_length()), 8)
                             if (v >> s) & 0xFF):
                    if v > 0xFF:
                        hits.append(l.index)
    return hits if len(hits) >= 2 else []


def _loops(ctx):
    return sorted({e['from'] for e in ctx.cfg.get('edges', []) if e.get('backward')})


def _indirect_calls(ctx):
    return [l.index for l in ctx.instructions
            if l.mnemonic in ('call', 'jmp', 'blr', 'br')
            and l.operands and l.operands[0].kind in ('register', 'memory')]


def _unbalanced_stack(ctx):
    pushes = len(ctx.find('push'))
    pops = len(ctx.find('pop'))
    if pushes and pops and abs(pushes - pops) >= 2:
        return sorted(set(ctx.find('push') + ctx.find('pop')))
    return []


def _syscall_sites(ctx):
    return [l.index for l in ctx.instructions
            if l.mnemonic in ('syscall', 'sysenter', 'svc')
            or (l.mnemonic == 'int' and l.operands
                and l.operands[0].kind == 'immediate' and l.operands[0].value == 0x80)]


PATTERNS = [
    # ---- structure -------------------------------------------------
    Pattern('fn_prologue', 'Function Prologue',
            'The caller’s frame pointer is saved and a new stack frame is opened — '
            'the conventional first two instructions of a function.',
            'info', 'structure', sequence=['push ebp', 'mov ebp, esp'], window=3),
    Pattern('fn_prologue64', 'Function Prologue (64-bit)',
            'The 64-bit form of the prologue: RBP is saved and re-pointed at the stack top.',
            'info', 'structure', sequence=['push rbp', 'mov rbp, rsp'], window=3),
    Pattern('fn_prologue_arm', 'Function Prologue (AArch64)',
            'Frame pointer and link register are stored as a pair — the AArch64 prologue.',
            'info', 'structure', sequence=['stp x29', 'mov x29'], window=3),
    Pattern('fn_epilogue', 'Function Epilogue',
            'The frame pointer is restored and control returns to the caller.',
            'info', 'structure', sequence=['pop ebp', 'ret'], window=3),
    Pattern('fn_epilogue64', 'Function Epilogue (64-bit)',
            'RBP is restored and control returns to the caller.',
            'info', 'structure', sequence=['pop rbp', 'ret'], window=3),
    Pattern('leave_ret', 'Leave / Return',
            'A one-instruction frame teardown followed by a return — the compact epilogue.',
            'info', 'structure', sequence=['leave', 'ret'], window=2),
    Pattern('stack_frame', 'Stack Frame with Locals',
            'After opening the frame, space is reserved on the stack for local variables.',
            'info', 'structure', sequence=['push ebp', 'mov ebp, esp', 'sub esp'], window=4),
    Pattern('cdecl_cleanup', 'cdecl Call Cleanup',
            'Arguments are popped by the caller after the call — the cdecl convention.',
            'info', 'structure', sequence=['call', 'add esp'], window=3),

    # ---- control flow ----------------------------------------------
    Pattern('loop_back', 'Loop',
            'A branch jumps backwards to an earlier label, so this block runs repeatedly.',
            'info', 'control', custom=_loops),
    Pattern('loop_instr', 'Counted Loop (LOOP)',
            'The LOOP instruction counts ECX down to zero — a fixed-iteration loop.',
            'info', 'control', any_of=['loop', 'loope', 'loopne']),
    Pattern('cond_branch', 'Conditional Branching',
            'Execution forks based on the flags set by an earlier comparison.',
            'info', 'control',
            any_of=['je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'jae', 'jbe',
                    'b.eq', 'b.ne', 'cbz', 'cbnz', 'beq', 'bne']),
    Pattern('comparison_check', 'Comparison Check',
            'A value is compared and the result steers a branch — the shape of an '
            'if-statement, a bounds check, or a password/licence test.',
            'notable', 'control', all_of=['cmp'], ),
    Pattern('switch_table', 'Jump Table / Switch',
            'An indirect jump through a computed address — typically a compiled switch statement.',
            'notable', 'control', regex=r'^jmp\s+(?:\[|\w+\s*\+)'),
    Pattern('indirect_call', 'Indirect Call',
            'A call or jump through a register or memory slot. The target is only known at '
            'run time, which defeats naive static analysis.',
            'notable', 'control', custom=_indirect_calls),
    Pattern('recursion_guard', 'Early Return',
            'A conditional branch jumps straight to a return — a guard clause or base case.',
            'info', 'control', sequence=['cmp', 'je', 'ret'], window=4),

    # ---- data / arithmetic -----------------------------------------
    Pattern('arithmetic', 'Arithmetic Operation',
            'Values are being computed rather than just moved around.',
            'info', 'data', any_of=['add', 'sub', 'imul', 'mul', 'idiv', 'div', 'inc', 'dec', 'neg']),
    Pattern('bit_manipulation', 'Bit Manipulation',
            'Shifts, rotates or masks — common in hashing, packing and crypto routines.',
            'info', 'data', any_of=['shl', 'shr', 'sar', 'sal', 'rol', 'ror', 'rcl', 'rcr', 'bt', 'bts'],
            min_count=2),
    Pattern('register_zeroing', 'Register Zeroing',
            'A register is cleared with `xor reg, reg` — two bytes instead of five.',
            'info', 'data', regex=r'^(?:xor|sub)\s+(\w+),\s*\1$'),
    Pattern('hardcoded_values', 'Hardcoded Constants',
            'Large literal values are embedded in the code. In a licence or auth routine '
            'these are often the magic number being checked against.',
            'notable', 'data', custom=_hardcoded_constants),
    Pattern('string_ops', 'String / Buffer Operations',
            'Block memory moves or scans — copying, comparing or searching a buffer.',
            'info', 'data',
            any_of=['movs', 'movsb', 'movsd', 'stos', 'stosb', 'lods', 'lodsb', 'scas', 'scasb',
                    'cmps', 'cmpsb', 'rep']),
    Pattern('stack_strings', 'Stack-Built Strings',
            'Printable characters are pushed as immediates and assembled on the stack. '
            'This hides strings from a simple `strings` scan.',
            'warning', 'obfuscation', custom=_stack_strings),
    Pattern('simd', 'SIMD / Vector Code',
            'Wide registers process several values per instruction — optimised bulk work.',
            'info', 'data', regex=r'\b[xy]mm\d'),

    # ---- system / security -----------------------------------------
    Pattern('syscall', 'System Call',
            'The code drops into the kernel directly rather than calling a library function. '
            'Normal for shellcode and static binaries; unusual inside ordinary application code.',
            'notable', 'system', custom=_syscall_sites),
    Pattern('nop_sled', 'NOP Sled',
            'A run of three or more NOPs. In exploit payloads this widens the window for an '
            'imprecise jump to land safely; in compiled code it is usually just alignment padding.',
            'warning', 'exploit', custom=_nop_sled),
    Pattern('repeated_push', 'Repeated Pushes',
            'Several consecutive pushes — a run of call arguments, or data staged on the stack.',
            'info', 'structure', custom=_repeated_push),
    Pattern('anti_debug_ptrace', 'Anti-Debugging: ptrace',
            'A PTRACE_TRACEME probe. If a debugger already holds the process the call fails, '
            'which is how the program notices it is being traced.',
            'warning', 'anti-analysis', regex=r'ptrace'),
    Pattern('anti_debug_timing', 'Anti-Debugging: Timing Check',
            'The cycle counter is sampled. Large gaps between samples reveal single-stepping.',
            'warning', 'anti-analysis', any_of=['rdtsc', 'rdtscp']),
    Pattern('anti_debug_int3', 'Breakpoint Instruction',
            'An INT3 trap. Debuggers insert these; code that executes or scans for them is '
            'often checking whether it has been patched.',
            'warning', 'anti-analysis', any_of=['int3']),
    Pattern('vm_detect', 'VM / Sandbox Detection',
            'CPUID is queried, a standard way to fingerprint a hypervisor.',
            'warning', 'anti-analysis', any_of=['cpuid']),
    Pattern('self_modifying', 'Self-Modifying Code',
            'The code writes to memory addressed relative to the instruction pointer — '
            'it is rewriting itself as it runs.',
            'warning', 'obfuscation', custom=_self_modifying),
    Pattern('privileged', 'Privileged Instructions',
            'Instructions that only run in ring 0 - driver, bootloader or rootkit '
            'territory. In a user-space program these would fault.',
            'warning', 'system',
            any_of=['lgdt', 'lidt', 'ltr', 'lmsw', 'clts', 'invd', 'invlpg',
                    'wrmsr', 'rdmsr', 'cli', 'sti']),
    Pattern('halt', 'Halt Instruction',
            'A HLT. Compilers emit one after a call that never returns, so on its own '
            'this is usually just a trap rather than anything privileged.',
            'info', 'system', any_of=['hlt']),
    Pattern('atomic', 'Atomic / Concurrent Access',
            'A LOCK prefix or compare-and-swap — shared state touched from several threads.',
            'info', 'system', any_of=['lock', 'cmpxchg', 'xadd']),
    Pattern('unbalanced_stack', 'Unbalanced Stack',
            'Pushes and pops do not line up in this listing. Often just a partial excerpt, '
            'but in full functions it points at a stack bug or a deliberate pivot.',
            'warning', 'structure', custom=_unbalanced_stack),
]


def detect(lines, meta, cfg=None):
    """Run every pattern. Returns a list of result dicts, severest first."""
    ctx = MatchContext(lines, meta, cfg)
    results = []
    for pattern in PATTERNS:
        try:
            hits = pattern.match(ctx)
        except Exception:
            hits = []
        if hits:
            results.append({
                'id': pattern.id,
                'name': pattern.name,
                'description': pattern.description,
                'severity': pattern.severity,
                'category': pattern.category,
                'lines': sorted(set(hits))[:40],
                'count': len(set(hits)),
            })
    order = {'warning': 0, 'notable': 1, 'info': 2}
    results.sort(key=lambda r: (order.get(r['severity'], 3), r['name']))
    return results
