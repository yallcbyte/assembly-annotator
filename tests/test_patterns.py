from annotator import analyse


def names(src):
    return {p['name'] for p in analyse(src)['patterns']}


def pattern(src, name):
    return next(p for p in analyse(src)['patterns'] if p['name'] == name)


def test_function_prologue_and_epilogue():
    src = 'push ebp\nmov ebp, esp\nsub esp, 16\nmov esp, ebp\npop ebp\nret'
    found = names(src)
    assert 'Function Prologue' in found
    assert 'Function Epilogue' in found
    assert 'Stack Frame with Locals' in found


def test_nop_sled_needs_at_least_three():
    assert 'NOP Sled' not in names('nop\nnop')
    assert 'NOP Sled' in names('nop\nnop\nnop\nnop')
    assert pattern('nop\nnop\nnop', 'NOP Sled')['lines'] == [1, 2, 3]


def test_loop_is_found_from_a_backward_branch():
    src = 'top:\n  dec ecx\n  jnz top'
    assert 'Loop' in names(src)
    assert analyse(src)['stats']['loops'] == 1


def test_forward_jump_is_not_a_loop():
    assert 'Loop' not in names('jmp done\nnop\ndone:\nret')


def test_anti_analysis_patterns():
    found = names('rdtsc\ncpuid\nint3')
    assert {'Anti-Debugging: Timing Check', 'VM / Sandbox Detection',
            'Breakpoint Instruction'} <= found


def test_stack_built_strings_are_flagged():
    p = pattern('push 0x68732f2f\npush 0x6e69622f', 'Stack-Built Strings')
    assert p['severity'] == 'warning'
    assert p['lines'] == [1, 2]


def test_syscall_sites_are_located():
    assert pattern('mov eax, 1\nint 0x80', 'System Call')['lines'] == [2]
    assert pattern('syscall', 'System Call')['lines'] == [1]


def test_int_other_than_0x80_is_not_a_linux_syscall():
    assert 'System Call' not in names('int 0x21')


def test_indirect_call_is_flagged():
    assert 'Indirect Call' in names('call eax')
    assert 'Indirect Call' not in names('call printf')


def test_patterns_carry_a_description_and_line_numbers():
    for p in analyse('push ebp\nmov ebp, esp\nret')['patterns']:
        assert p['description'] and p['severity'] in ('info', 'notable', 'warning')
        assert p['lines'] and all(isinstance(n, int) for n in p['lines'])


def test_results_are_ordered_most_severe_first():
    sev = [p['severity'] for p in analyse(
        'nop\nnop\nnop\ncmp eax, 1\nje out\nout:\nret')['patterns']]
    rank = {'warning': 0, 'notable': 1, 'info': 2}
    assert sev == sorted(sev, key=lambda s: rank[s])


def test_att_listings_match_intel_spelled_patterns():
    # `push %rbp` must satisfy a pattern written as `push rbp`.
    src = 'pushq %rbp\nmovq %rsp, %rbp\nsubq $0x10, %rsp\nleave\nret'
    found = names(src)
    assert 'Function Prologue (64-bit)' in found
    assert 'Leave / Return' in found


def test_objdump_paste_is_recognised_end_to_end():
    src = ('0000000000001129 <main>:\n'
           '    1129:\t55                   \tpush   %rbp\n'
           '    112a:\t48 89 e5             \tmov    %rsp,%rbp\n'
           '    1141:\tc9                   \tleave\n'
           '    1142:\tc3                   \tret\n')
    r = analyse(src)
    assert r['stats']['unknown_mnemonics'] == []
    assert 'Function Prologue (64-bit)' in {p['name'] for p in r['patterns']}


def test_64bit_epilogue_is_detected():
    assert 'Function Epilogue (64-bit)' in names('pop rbp\nret')
    assert 'Function Epilogue (64-bit)' in names('popq %rbp\nret')
