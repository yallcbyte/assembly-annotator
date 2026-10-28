"""Run the CIL pipeline and return the same result shape as native code.

Keeping the shape identical is what lets the existing Lines, Graph and Stack
views, the exports and the pattern panel work on .NET without forking.
"""

import re
from collections import Counter

from .. import cfg as cfg_mod, deobf
from . import isa, patterns
from .explain import CilExplainer
from .parser import parse

BRANCHES = set(isa.BRANCH_OPCODES) | {'switch'}
TERMINATORS = {'ret', 'throw', 'rethrow', 'br', 'br.s', 'jmp', 'leave', 'leave.s',
               'endfinally', 'endfilter'}


def analyse(code: str, verbosity: str = 'normal') -> dict:
    aliaser = deobf.NameAliaser()
    code = aliaser.sub(code)
    lines, meta = parse(code)
    graph = cfg_mod.build(lines, BRANCHES, TERMINATORS)

    explainer = CilExplainer(meta['locals'], meta['maxstack'], verbosity)
    annotations = [explainer.explain(line) for line in lines]

    by_index = {a['index']: a for a in annotations}
    for edge in graph['edges']:
        a = by_index.get(edge['from'])
        if a is not None and edge.get('to') is not None:
            a['jump_target'] = edge['to']
            a['jump_backward'] = edge['backward']
    for idx in graph['loop_headers']:
        if idx in by_index:
            by_index[idx]['loop_header'] = True
    for item in graph['unresolved']:
        a = by_index.get(item['from'])
        if a is not None:
            a['notes'].append(f'Branch target `{item["target"]}` is not in this listing.')

    for a in annotations:
        a['raw'] = deobf.neutralise_bidi(a['raw'])
    detected = patterns.detect(annotations, lines)
    named = aliaser.describe()
    if named:
        hit = sorted({a['index'] for a in annotations if re.search(r'\bobf_\d+\b', a['raw'])})
        detected.insert(0, {
            'id': 'invisible_names', 'name': 'Obfuscated Names', 'severity': 'warning',
            'category': 'obfuscation',
            'description': ('Names made of invisible Unicode — zero-width spaces and '
                            'right-to-left overrides — so they carry no meaning. Shown here '
                            'as obf_1, obf_2 …'),
            'lines': hit[:40], 'count': len(hit),
            'evidence': [f'{d["alias"]}: {d["length"]} chars' for d in named[:6]],
        })
    blocks = cfg_mod.basic_blocks(lines, graph, BRANCHES, TERMINATORS)
    frame = _frame(meta, explainer)

    return {
        'meta': {k: v for k, v in meta.items() if k not in ('locals',)},
        'annotations': annotations,
        'patterns': detected,
        'cfg': {
            'labels': graph['labels'],
            'edges': graph['edges'],
            'loop_headers': graph['loop_headers'],
            'unreachable': graph['unreachable'],
            'functions': [m['line'] for m in meta['methods']],
            'blocks': blocks['blocks'],
            'block_edges': blocks['edges'],
        },
        'frame': frame,
        'stats': _stats(annotations, meta, graph, detected, blocks, explainer),
    }


def _frame(meta, explainer) -> dict:
    """The CIL analogue of a stack frame: typed local slots plus stack depth."""
    slots = []
    for local in meta['locals']:
        n = local['slot']
        slots.append({
            'base': 'local', 'offset': n, 'size': None,
            'addr_label': f'V_{n}',
            'name': local['name'] or f'local {n}',
            'type_text': local['type'],
            'role': 'local',
            'detail': f'Declared as {local["type"]}.',
            'reads': explainer.local_reads.get(n, []),
            'writes': explainer.local_writes.get(n, []),
        })
    return {
        'kind': 'cil',
        'has_frame': bool(slots),
        'word': None,
        'reserved': 0,
        'slots': slots,
        'arguments': [],
        'locals': slots,
        'maxstack': meta['maxstack'],
        'max_depth_seen': explainer.max_seen,
        'underflowed': explainer.underflowed,
        'prologue_lines': [], 'epilogue_lines': [], 'max_depth': explainer.max_seen,
    }


def _stats(annotations, meta, graph, detected, blocks, explainer) -> dict:
    instrs = [a for a in annotations if a['kind'] == 'instruction']
    categories = Counter(a['category'] for a in instrs)
    unknown = sorted({a['mnemonic'] for a in instrs if not isa.lookup(a['mnemonic'])})
    calls = [a['call'] for a in annotations if a.get('call')]
    targets = Counter(c['target'] for c in calls)
    return {
        'instructions': len(instrs),
        'lines': meta['total_lines'],
        'labels': len(meta['methods']),
        'branches': len(graph['edges']),
        'loops': len(graph['loop_headers']),
        'functions': len(meta['methods']),
        'blocks': len(blocks['blocks']),
        'coverage': round(100 * (len(instrs) - sum(1 for a in instrs
                                                    if not isa.lookup(a['mnemonic'])))
                          / len(instrs), 1) if instrs else 100.0,
        'unknown_mnemonics': unknown,
        'syscalls': [],
        'calls': len(calls),
        'call_targets': [{'target': t, 'count': n} for t, n in targets.most_common(20)],
        'methods': [m['name'] for m in meta['methods'] if m.get('name')],
        'max_stack': explainer.max_seen,
        'categories': [
            {'id': cid, 'label': isa.CATEGORIES.get(cid, {}).get('label', cid.title()),
             'colour': isa.CATEGORIES.get(cid, {}).get('colour', '#90a4ae'), 'count': n}
            for cid, n in categories.most_common()
        ],
        'top_mnemonics': [{'mnemonic': m, 'count': n} for m, n in
                          Counter(a['mnemonic'] for a in instrs).most_common(8)],
        'warnings': [p['name'] for p in detected if p['severity'] == 'warning'],
    }
