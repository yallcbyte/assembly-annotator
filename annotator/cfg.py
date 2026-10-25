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


def build(lines, branch_mnemonics=None, terminators=None):
    """Return labels, branch edges, loop headers and unreachable lines.

    `branch_mnemonics` and `terminators` let a non-native instruction set (CIL)
    reuse this analysis: without them the x86/ARM/MIPS heuristics apply.
    """
    branches = set(branch_mnemonics) if branch_mnemonics else None
    stops = set(terminators) if terminators else TERMINATORS

    def is_branch(mnemonic):
        if branches is not None:
            return mnemonic in branches
        return (mnemonic in BRANCH_MNEMONICS or mnemonic.startswith('j')
                or mnemonic.startswith('b.'))
    labels = {}
    for line in lines:
        if line.label:
            labels[line.label] = line.index
            labels[line.label.lstrip('.')] = line.index

    instructions = [l for l in lines if l.kind == 'instruction']
    edges, unresolved = [], []

    for line in instructions:
        m = line.mnemonic or ''
        if not is_branch(m):
            continue
        if not line.operands:
            continue
        target_op = line.operands[-1]
        if target_op.kind in ('register', 'memory'):
            edges.append({'from': line.index, 'to': None, 'target': target_op.text,
                          'kind': 'indirect', 'backward': False,
                          'conditional': not m.startswith(('jmp', 'call', 'b', 'j'))})
            continue
        if branches is not None and len(line.operands) > 1:
            # `switch (IL_0010, IL_0020)` has one edge per target.
            for op in line.operands:
                to = labels.get(op.text.strip())
                if to is not None:
                    edges.append({'from': line.index, 'to': to, 'target': op.text.strip(),
                                  'kind': 'jump', 'backward': to < line.index,
                                  'conditional': True})
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
            'conditional': m not in ('jmp', 'call', 'b', 'bl', 'j', 'jal',
                                     'br', 'br.s', 'leave', 'leave.s'),
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
            prev_terminated = (line.mnemonic in stops)
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


def _label_above(lines, start):
    """The label immediately preceding an instruction.

    Walks back past blank and comment lines only, so the nearest real label
    wins rather than the first one inside an arbitrary window.
    """
    by_index = {l.index: l for l in lines}
    own = by_index.get(start)
    if own is not None and own.label:
        return own.label
    for i in range(start - 1, 0, -1):
        line = by_index.get(i)
        if line is None:
            continue
        if line.label:
            return line.label
        if line.kind in ('blank', 'comment'):
            continue
        break
    return None


def basic_blocks(lines, graph, branch_mnemonics=None, terminators=None):
    """Group instructions into basic blocks with successor edges.

    A block starts at the entry, at any branch target, at a label, or right
    after a branch; it ends at a terminator or just before the next start.
    """
    instructions = [l for l in lines if l.kind == 'instruction']
    if not instructions:
        return {'blocks': [], 'edges': []}

    index_of = {l.index: i for i, l in enumerate(instructions)}
    targets = {e['to'] for e in graph['edges'] if e.get('to')}

    # Labels sit on their own line, so a target may name the label rather than
    # the instruction under it. Walk forward to the next real instruction.
    def first_instruction_at_or_after(line_index):
        for l in instructions:
            if l.index >= line_index:
                return l.index
        return None

    starts = {instructions[0].index}
    for t in targets:
        resolved = first_instruction_at_or_after(t)
        if resolved is not None:
            starts.add(resolved)
    for i, l in enumerate(instructions):
        if l.label:
            starts.add(l.index)
        m = l.mnemonic or ''
        if branch_mnemonics is not None:
            is_branch = m in branch_mnemonics or m in (terminators or TERMINATORS)
        else:
            is_branch = (m in BRANCH_MNEMONICS or m.startswith('j')
                         or m.startswith('b.') or m in TERMINATORS)
        if is_branch and i + 1 < len(instructions):
            starts.add(instructions[i + 1].index)

    # Loop headers are recorded against the label line; blocks begin at the
    # first instruction under it, so resolve them the same way targets are.
    loop_entries = set()
    for header in graph['loop_headers']:
        resolved = first_instruction_at_or_after(header)
        if resolved is not None:
            loop_entries.add(resolved)
    for e in graph['edges']:
        if e.get('backward') and e.get('to') is not None:
            resolved = first_instruction_at_or_after(e['to'])
            if resolved is not None:
                loop_entries.add(resolved)

    ordered_starts = sorted(starts)
    blocks = []
    for n, start in enumerate(ordered_starts):
        end_exclusive = ordered_starts[n + 1] if n + 1 < len(ordered_starts) else None
        members = [l for l in instructions
                   if l.index >= start and (end_exclusive is None or l.index < end_exclusive)]
        if not members:
            continue
        label = _label_above(lines, start)
        blocks.append({
            'id': len(blocks),
            'start': members[0].index,
            'end': members[-1].index,
            'label': label,
            'lines': [l.index for l in members],
            'terminator': members[-1].mnemonic,
            'loop_header': members[0].index in loop_entries,
        })

    block_at = {}
    for b in blocks:
        for line in b['lines']:
            block_at[line] = b['id']

    edges = []
    for n, b in enumerate(blocks):
        last_line = b['end']
        last = instructions[index_of[last_line]]
        m = last.mnemonic or ''
        outgoing = [e for e in graph['edges'] if e['from'] == last_line]
        jump = next((e for e in outgoing if e['kind'] in ('jump', 'indirect')), None)

        if jump and jump.get('to') is not None:
            resolved = first_instruction_at_or_after(jump['to'])
            if resolved in block_at:
                edges.append({'from': b['id'], 'to': block_at[resolved],
                              'kind': 'taken' if jump['conditional'] else 'jump',
                              'backward': jump['backward']})
        elif jump:
            edges.append({'from': b['id'], 'to': None, 'kind': 'indirect', 'backward': False})

        stops = set(terminators) if terminators else TERMINATORS
        falls_through = m not in stops or (jump and jump['conditional'])
        if falls_through and n + 1 < len(blocks):
            edges.append({'from': b['id'], 'to': blocks[n + 1]['id'],
                          'kind': 'fallthrough', 'backward': False})

    return {'blocks': blocks, 'edges': edges}
