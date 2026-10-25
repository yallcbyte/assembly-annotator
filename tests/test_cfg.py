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
