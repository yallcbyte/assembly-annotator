from annotator import analyse


def test_branch_targets_resolve_to_line_numbers():
    r = analyse('jmp done\nnop\ndone:\nret')
    edge = r['cfg']['edges'][0]
    assert edge['from'] == 1 and edge['to'] == 3 and edge['backward'] is False


def test_backward_branch_is_marked():
    r = analyse('top:\nnop\njmp top')
    assert r['cfg']['edges'][0]['backward'] is True
    assert r['cfg']['loop_headers'] == [1]


def test_unreachable_code_is_detected():
    r = analyse('ret\nmov eax, 1')
    assert 2 in r['cfg']['unreachable']


def test_code_after_a_conditional_jump_is_reachable():
    assert analyse('je skip\nmov eax, 1\nskip:\nret')['cfg']['unreachable'] == []


def test_unresolved_branch_target_is_noted():
    r = analyse('jmp nowhere')
    assert 'not defined in this listing' in ' '.join(r['annotations'][0]['notes'])


def test_call_targets_count_as_functions():
    r = analyse('call helper\nret\nhelper:\nret')
    assert r['cfg']['functions'] == [3]


def test_indirect_branch_has_no_resolved_target():
    r = analyse('jmp eax')
    assert r['cfg']['edges'][0]['kind'] == 'indirect'
    assert r['cfg']['edges'][0]['to'] is None


def test_branches_to_local_dot_labels_resolve():
    src = ('check:\n  cmp eax, 1\n  jne .denied\n  jmp .done\n'
           '.denied:\n  xor eax, eax\n.done:\n  ret')
    r = analyse(src)
    targets = {e['from']: e['to'] for e in r['cfg']['edges']}
    assert targets == {3: 5, 4: 7}
    assert r['stats']['branches'] == 2


# ---- basic blocks -------------------------------------------------------

def blocks_of(src):
    from annotator.parser import parse
    from annotator import cfg as cfg_mod
    lines, _ = parse(src)
    graph = cfg_mod.build(lines)
    return cfg_mod.basic_blocks(lines, graph)


IF_ELSE = """check:
  push ebp
  mov ebp, esp
  cmp eax, 1
  jne .denied
  mov eax, 1
  jmp .done
.denied:
  xor eax, eax
.done:
  pop ebp
  ret"""


def test_if_else_splits_into_four_blocks():
    assert len(blocks_of(IF_ELSE)['blocks']) == 4


def test_each_block_takes_the_label_directly_above_it():
    labels = [b['label'] for b in blocks_of(IF_ELSE)['blocks']]
    assert labels == ['check', None, '.denied', '.done']


def test_conditional_branch_produces_both_taken_and_fallthrough():
    kinds = {(e['from'], e['to']): e['kind'] for e in blocks_of(IF_ELSE)['edges']}
    assert kinds[(0, 2)] == 'taken'
    assert kinds[(0, 1)] == 'fallthrough'


def test_unconditional_jump_has_no_fallthrough():
    edges = [e for e in blocks_of(IF_ELSE)['edges'] if e['from'] == 1]
    assert [e['kind'] for e in edges] == ['jump']


def test_loop_header_block_is_marked():
    bb = blocks_of('top:\n  dec ecx\n  jnz top\n  ret')
    assert bb['blocks'][0]['loop_header'] is True
    assert bb['blocks'][1]['loop_header'] is False


def test_self_loop_edge_points_at_its_own_block():
    bb = blocks_of('a:\n  nop\n  jmp a')
    assert bb['edges'][0]['from'] == bb['edges'][0]['to'] == 0
    assert bb['edges'][0]['backward'] is True


def test_every_instruction_lands_in_exactly_one_block():
    from annotator.parser import parse
    bb = blocks_of(IF_ELSE)
    lines, _ = parse(IF_ELSE)
    expected = [l.index for l in lines if l.kind == 'instruction']
    seen = [n for b in bb['blocks'] for n in b['lines']]
    assert sorted(seen) == expected
    assert len(seen) == len(set(seen))


def test_empty_listing_yields_no_blocks():
    assert blocks_of('; nothing here')['blocks'] == []
