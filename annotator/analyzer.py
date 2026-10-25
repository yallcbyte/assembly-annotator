"""Top-level orchestration: text in, full analysis out."""

from collections import Counter

from . import cfg as cfg_mod, frames as frames_mod, isa, patterns as patterns_mod
from .explain import Explainer
from .parser import parse

MAX_INPUT_CHARS = 200_000
MAX_LINES = 20_000


class InputTooLarge(ValueError):
    pass


def analyse(code: str, arch=None, syntax=None, verbosity='normal'):
    if len(code) > MAX_INPUT_CHARS:
        raise InputTooLarge(
            f'Input is {len(code)} characters; the limit is {MAX_INPUT_CHARS}.')
    if code.count('\n') > MAX_LINES:
        raise InputTooLarge(f'Input has more than {MAX_LINES} lines.')

    lines, meta = parse(code, arch=arch, syntax=syntax)
    graph = cfg_mod.build(lines)

    explainer = Explainer(meta['arch'], meta['syntax'], verbosity)
    annotations = [explainer.explain(line) for line in lines]

    # Attach control-flow information to the lines it belongs to.
    by_index = {a['index']: a for a in annotations}
    for edge in graph['edges']:
        a = by_index.get(edge['from'])
        if a is not None:
            a['jump_target'] = edge['to']
            a['jump_backward'] = edge['backward']
    for idx in graph['loop_headers']:
        if idx in by_index:
            by_index[idx]['loop_header'] = True
    for idx in graph['unreachable']:
        if idx in by_index:
            by_index[idx]['unreachable'] = True
            by_index[idx]['notes'].append(
                'Nothing in this listing reaches this line — dead code, or the '
                'entry point is outside the excerpt.')
    for item in graph['unresolved']:
        a = by_index.get(item['from'])
        if a is not None:
            a['notes'].append(
                f'Branch target `{item["target"]}` is not defined in this listing.')

    detected = patterns_mod.detect(lines, meta, graph)
    blocks = cfg_mod.basic_blocks(lines, graph)
    frame = frames_mod.analyse_frame(lines, meta['arch'])
    stats = _summarise(annotations, meta, graph, detected)
    stats['blocks'] = len(blocks['blocks'])

    return {
        'meta': meta,
        'annotations': annotations,
        'patterns': detected,
        'cfg': {
            'labels': graph['labels'],
            'edges': graph['edges'],
            'loop_headers': graph['loop_headers'],
            'unreachable': graph['unreachable'],
            'functions': graph['functions'],
            'blocks': blocks['blocks'],
            'block_edges': blocks['edges'],
        },
        'frame': frame,
        'stats': stats,
    }


def _summarise(annotations, meta, graph, detected):
    categories = Counter(a['category'] for a in annotations
                         if a['kind'] == 'instruction')
    mnemonics = Counter(a['mnemonic'] for a in annotations
                        if a['kind'] == 'instruction' and a['mnemonic'])
    unknown = [a['mnemonic'] for a in annotations
               if a['kind'] == 'instruction' and not isa.lookup(a['mnemonic'], meta['arch'])]
    syscalls_used = sorted({a['syscall'] for a in annotations if a.get('syscall')})

    return {
        'instructions': meta['instruction_count'],
        'lines': meta['total_lines'],
        'labels': meta['label_count'],
        'branches': graph['branch_count'],
        'loops': len(graph['loop_headers']),
        'functions': len(graph['functions']),
        'coverage': round(
            100 * (meta['instruction_count'] - len(unknown)) / meta['instruction_count'], 1)
            if meta['instruction_count'] else 100.0,
        'unknown_mnemonics': sorted(set(unknown)),
        'syscalls': syscalls_used,
        'categories': [
            {'id': cid, 'label': isa.CATEGORIES.get(cid, {}).get('label', cid.title()),
             'colour': isa.CATEGORIES.get(cid, {}).get('colour', '#90a4ae'), 'count': n}
            for cid, n in categories.most_common()
        ],
        'top_mnemonics': [{'mnemonic': m, 'count': n} for m, n in mnemonics.most_common(8)],
        'warnings': [p['name'] for p in detected if p['severity'] == 'warning'],
    }
