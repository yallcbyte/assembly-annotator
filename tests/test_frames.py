import pytest

from annotator.frames import analyse_frame
from annotator.parser import parse


def frame(src):
    lines, meta = parse(src)
    return analyse_frame(lines, meta['arch'])


CDECL = """check:
    push ebp
    mov ebp, esp
    sub esp, 0x20
    mov eax, [ebp+8]
    mov ecx, [ebp+12]
    mov dword [ebp-4], 0
    mov [ebp-8], eax
    mov esp, ebp
    pop ebp
    ret"""


def test_prologue_and_reserved_size_are_found():
    f = frame(CDECL)
    assert f['has_frame'] is True
    assert f['reserved'] == 0x20
    assert f['prologue_lines'] == [2, 3, 4]


def test_epilogue_is_found():
    assert frame(CDECL)['epilogue_lines'] == [9, 10, 11]


def test_arguments_are_numbered_from_the_first():
    # [ebp+0] saved ebp, [ebp+4] return address, [ebp+8] is argument 1.
    args = {s['offset']: s['name'] for s in frame(CDECL)['arguments']}
    assert args == {8: 'argument 1', 12: 'argument 2'}


def test_locals_are_below_the_frame_pointer():
    offsets = sorted(s['offset'] for s in frame(CDECL)['locals'])
    assert offsets == [-8, -4]


def test_saved_pointer_and_return_address_are_implied():
    roles = {s['role'] for s in frame(CDECL)['slots']}
    assert {'saved', 'return'} <= roles


def test_reads_and_writes_are_tracked_separately():
    slots = {s['offset']: s for s in frame(CDECL)['slots']}
    assert slots[8]['reads'] == [5] and slots[8]['writes'] == []
    assert slots[-4]['writes'] == [7] and slots[-4]['reads'] == []


def test_operand_size_prefix_is_honoured():
    f = frame('push ebp\nmov ebp, esp\nmov byte [ebp-1], 0\nmov qword [ebp-16], rax')
    sizes = {s['offset']: s['size'] for s in f['slots']}
    assert sizes[-1] == 1
    assert sizes[-16] == 8


def test_att_memory_operands_are_understood():
    f = frame('pushq %rbp\nmovq %rsp, %rbp\nmovl $0, -0x4(%rbp)\nmovl 0x10(%rbp), %eax')
    offsets = {s['offset'] for s in f['slots']}
    assert -4 in offsets and 16 in offsets


def test_64bit_argument_numbering_uses_an_8_byte_word():
    f = frame('push rbp\nmov rbp, rsp\nmov rax, [rbp+16]\nmov rcx, [rbp+24]')
    assert f['word'] == 8
    assert {s['offset']: s['name'] for s in f['arguments']} == {16: 'argument 1', 24: 'argument 2'}


def test_esp_relative_slots_are_separated_from_frame_slots():
    f = frame('push ebp\nmov ebp, esp\nmov eax, [esp+4]\nmov ecx, [ebp-4]')
    bases = {(s['base'], s['offset']) for s in f['slots']}
    assert ('stack', 4) in bases
    assert ('frame', -4) in bases


def test_enter_instruction_counts_as_a_prologue():
    f = frame('enter 32, 0\nmov eax, [ebp-4]\nleave\nret')
    assert f['has_frame'] is True and f['reserved'] == 32


def test_listing_without_a_frame_reports_none():
    f = frame('xor eax, eax\nret')
    assert f['has_frame'] is False
    assert f['slots'] == []


def test_frame_analysis_survives_junk_operands():
    f = frame('mov eax, [\nmov ebx, []\nmov ecx, [ebp+')
    assert isinstance(f['slots'], list)
