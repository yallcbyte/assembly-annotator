import pytest

from annotator.parser import parse, split_operands, strip_comment, decode_immediate


def kinds(src):
    lines, _ = parse(src)
    return [l.kind for l in lines]


def test_labels_are_not_instructions():
    lines, _ = parse('loop_start:\n    add eax, ecx')
    assert lines[0].kind == 'label'
    assert lines[0].label == 'loop_start'
    assert lines[1].kind == 'instruction'


def test_label_with_instruction_on_same_line():
    lines, _ = parse('done: ret')
    assert lines[0].label == 'done'
    assert lines[0].mnemonic == 'ret'


def test_directives_are_classified():
    lines, _ = parse('section .text\n    global _start\n.globl main')
    assert [l.kind for l in lines] == ['directive', 'directive', 'directive']


def test_comment_only_line():
    lines, _ = parse('; just a note')
    assert lines[0].kind == 'comment'
    assert lines[0].comment == 'just a note'


def test_trailing_comment_is_separated():
    lines, _ = parse('mov eax, 1   ; set the return value')
    assert lines[0].mnemonic == 'mov'
    assert lines[0].comment == 'set the return value'
    assert len(lines[0].operands) == 2


@pytest.mark.parametrize('src,expected', [
    ('mov eax, 1', ['eax', '1']),
    ('mov dword [ebp-4], 0', ['dword [ebp-4]', '0']),
    ('lea eax, [ebx+ecx*4]', ['eax', '[ebx+ecx*4]']),
    ('db "a,b", 0', ['"a,b"', '0']),
])
def test_operand_splitting(src, expected):
    assert split_operands(src.split(None, 1)[1]) == expected


def test_att_operands_are_reordered_to_destination_first():
    lines, meta = parse('movl $42, %eax')
    assert meta['syntax'] == 'att'
    assert lines[0].operands[0].register == 'eax'
    assert lines[0].operands[1].kind == 'immediate'
    assert lines[0].operands[1].value == 42


def test_objdump_prefix_is_stripped():
    lines, _ = parse('    1129:\t55                   \tpush   %rbp')
    assert lines[0].address == '1129'
    assert lines[0].mnemonic == 'push'
    assert lines[0].opcodes == '55'


def test_rep_prefix_keeps_the_real_mnemonic():
    lines, _ = parse('rep movsb')
    assert lines[0].prefix == 'rep'
    assert lines[0].mnemonic == 'movsb'


def test_arch_detection():
    _, x86 = parse('mov eax, 1\nint 0x80')
    _, arm = parse('stp x29, x30, [sp, #-16]!\nbl foo\nsvc #0')
    _, mips = parse('lw $t0, 0($sp)\njal main')
    assert (x86['arch'], arm['arch'], mips['arch']) == ('x86', 'arm', 'mips')


@pytest.mark.parametrize('text,value', [
    ('0x1337', 0x1337), ('$42', 42), ('#16', 16), ('0b1010', 10),
    ('1Fh', 31), ('-8', -8), ('notanumber', None),
])
def test_immediate_decoding(text, value):
    assert decode_immediate(text) == value


def test_semicolon_inside_a_string_is_not_a_comment():
    code, comment = strip_comment('db "a;b", 0')
    assert comment is None
    assert code.strip() == 'db "a;b", 0'


def test_blank_lines_are_preserved_for_numbering():
    lines, _ = parse('nop\n\n\nnop')
    assert [l.index for l in lines] == [1, 2, 3, 4]
    assert kinds('nop\n\n\nnop') == ['instruction', 'blank', 'blank', 'instruction']


def test_dot_prefixed_local_labels_are_labels_not_directives():
    lines, _ = parse('.denied:\n    xor eax, eax\n.L2:\n    ret')
    assert lines[0].kind == 'label' and lines[0].label == '.denied'
    assert lines[2].kind == 'label' and lines[2].label == '.L2'


def test_dot_directive_without_a_colon_is_still_a_directive():
    lines, _ = parse('.globl main\n.text')
    assert [l.kind for l in lines] == ['directive', 'directive']


def test_ret_alone_does_not_make_a_listing_look_like_arm():
    # `ret` and `bl` exist on both sides (bl is also an x86 register),
    # so neither should outvote the x86 registers actually present.
    assert parse('pop rbp\nret')[1]['arch'] == 'x86'
    assert parse('popq %rbp\nret')[1]['arch'] == 'x86'
    assert parse('mov bl, 1\nret')[1]['arch'] == 'x86'


def test_genuine_arm_is_still_detected():
    assert parse('stp x29, x30, [sp, #-16]!\nret')[1]['arch'] == 'arm'
    assert parse('bl printf\nret')[1]['arch'] == 'arm'
