from annotator import analyse


def titles(src, **kw):
    return {a['index']: a['title'] for a in analyse(src, **kw)['annotations']}


def test_operands_appear_in_the_explanation():
    assert 'ECX' in titles('mov ecx, 5')[1]
    assert '5' in titles('mov ecx, 5')[1]


def test_xor_self_is_recognised_as_zeroing():
    assert titles('xor eax, eax')[1] == 'Zero out EAX'


def test_sub_self_is_also_zeroing():
    assert titles('sub ebx, ebx')[1] == 'Zero out EBX'


def test_test_self_is_a_zero_check():
    assert 'is zero' in titles('test eax, eax')[1]


def test_prologue_idioms():
    t = titles('push ebp\nmov ebp, esp\nsub esp, 32')
    assert 'frame pointer' in t[1]
    assert 'frame pointer' in t[2]
    assert '32 bytes' in t[3]


def test_shift_is_explained_as_multiplication():
    assert 'Multiply EAX by 8' == titles('shl eax, 3')[1]
    assert 'Divide EAX by 4' in titles('shr eax, 2')[1]


def test_mask_idiom():
    assert 'lowest byte' in titles('and eax, 0xFF')[1]


def test_syscall_number_is_resolved_through_register_tracking():
    t = titles('mov eax, 4\nmov ebx, 1\nint 0x80')
    assert 'write()' in t[3]


def test_x64_syscall_table_is_used_for_syscall_instruction():
    t = titles('mov rax, 60\nxor rdi, rdi\nsyscall')
    assert 'exit()' in t[3]


def test_unknown_syscall_number_degrades_gracefully():
    t = titles('mov eax, 61234\nint 0x80')
    assert 'system call' in t[2].lower()


def test_syscall_without_a_known_number_says_so():
    result = analyse('int 0x80')
    note = ' '.join(result['annotations'][0]['notes'])
    assert 'does not set' in note


def test_packed_ascii_immediate_is_decoded():
    notes = ' '.join(analyse('push 0x6e69622f')['annotations'][0]['notes'])
    assert '/bin' in notes


def test_labels_and_directives_get_real_explanations():
    t = titles('section .text\nmy_label:')
    assert 'Unknown' not in t[1] and 'Unknown' not in t[2]
    assert 'section' in t[1].lower()
    assert 'my_label' in t[2]


def test_unknown_mnemonic_is_reported_but_does_not_crash():
    result = analyse('frobnicate eax, ebx')
    assert 'not in the instruction database' in result['annotations'][0]['title']
    assert result['stats']['unknown_mnemonics'] == ['frobnicate']


def test_verbose_mode_adds_tracked_register_values():
    result = analyse('mov eax, 7\nadd eax, 3\ninc eax', verbosity='verbose')
    notes = ' '.join(result['annotations'][2]['notes'])
    assert '10' in notes


def test_att_syntax_reads_in_destination_first_order():
    t = titles('movl $42, %eax')
    assert 'EAX' in t[1] and '42' in t[1]


def test_arm_listing_is_explained():
    t = titles('stp x29, x30, [sp, #-16]!\nmov x29, sp\nret')
    assert 'Unknown' not in ' '.join(t.values())


def test_conditional_jump_names_its_condition():
    assert 'not equal' in titles('cmp eax, 1\njne target')[2]
