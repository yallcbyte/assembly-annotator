"""Light control-flow analysis.

Resolves branch targets to the lines that define them, which lets the UI draw
jump links, mark loop bodies and point out code nothing reaches.
"""

BRANCH_MNEMONICS = {
    'jmp', 'call', 'loop', 'loope', 'loopne', 'b', 'bl', 'blr', 'br',
    'j', 'jal', 'jr', 'cbz', 'cbnz', 'beq', 'bne',
}

TERMINATORS = {'ret', 'retn', 'iret', 'jmp', 'hlt', 'ud2', 'b', 'jr'}


def _is_branch(line) -> bool:
    m = line.mnemonic or ''
    return m in BRANCH_MNEMONICS or m.startswith(('j', 'b.')) and m not in ('jmp',) or m in BRANCH_MNEMONICS


def build(lines):
    """Return labels, branch edges, loop headers and unreachable lines."""
    labels = {}
    for line in lines:
        if line.label:
            labels[line.label] = line.index
            labels[line.label.lstrip('.')] = line.index

    instructions = [l for l in lines if l.kind == 'instruction']
    edges, unresolved = [], []

    for line in instructions:
        m = line.mnemonic or ''
        if not (m in BRANCH_MNEMONICS or m.startswith('j') or m.startswith('b.')):
            continue
        if not line.operands:
            continue
        target_op = line.operands[-1]
        if target_op.kind in ('register', 'memory'):
            edges.append({'from': line.index, 'to': None, 'target': target_op.text,
                          'kind': 'indirect', 'backward': False,
                          'conditional': not m.startswith(('jmp', 'call', 'b', 'j'))})
            continue
        name = target_op.text.strip()
        to = labels.get(name) or labels.get(name.lstrip('.'))
        if to is None:
            unresolved.append({'from': line.index, 'target': name})
            continue
        edges.append({
            'from': line.index,
            'to': to,
            'target': name,
            'kind': 'call' if m in ('call', 'bl', 'jal') else 'jump',
            'backward': to < line.index,
            'conditional': m not in ('jmp', 'call', 'b', 'bl', 'j', 'jal'),
        })

    loop_headers = sorted({e['to'] for e in edges if e.get('backward') and e['kind'] == 'jump'})

    # Lines reachable by falling through or by being a branch target.
    targets = {e['to'] for e in edges if e['to']}
    reachable, prev_terminated = set(), False
    for line in lines:
        if line.kind != 'instruction':
            if line.label and line.index in targets:
                prev_terminated = False
            continue
        if not prev_terminated or line.index in targets or line.label:
            reachable.add(line.index)
            prev_terminated = (line.mnemonic in TERMINATORS)
        elif line.index in targets:
            reachable.add(line.index)
            prev_terminated = False
    unreachable = [l.index for l in instructions if l.index not in reachable]

    # Entry points: exported/`_start`-style labels, and anything called.
    called = {e['to'] for e in edges if e['kind'] == 'call' and e['to']}
    functions = sorted({idx for name, idx in labels.items()
                        if idx in called or name in ('_start', 'main', 'start')})

    return {
        'labels': {k: v for k, v in labels.items()},
        'edges': edges,
        'unresolved': unresolved,
        'loop_headers': loop_headers,
        'unreachable': unreachable,
        'functions': functions,
        'branch_count': len(edges),
    }
