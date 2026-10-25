import pytest

from annotator.cil import il_decoder as d
from annotator.cil import isa


class Resolver:
    """Stands in for an assembly: tokens -> names."""
    methods = {0x0A000001: 'void [mscorlib]System.Console::WriteLine(string)',
               0x06000002: 'instance void Program::.ctor()'}
    strings = {0x70000001: 'hi "there"\n'}
    types = {0x01000003: '[mscorlib]System.Int32'}

    def method(self, tok):
        return self.methods.get(tok)

    def string(self, tok):
        return self.strings.get(tok)

    def type(self, tok):
        return self.types.get(tok)


def decode(hexstr, resolver=Resolver()):
    return d.decode(bytes.fromhex(hexstr.replace(' ', '')), resolver)


def test_every_decodable_opcode_is_known_to_the_annotator():
    names = [n for n, _ in list(d.ONE_BYTE.values()) + list(d.TWO_BYTE.values())]
    assert [n for n in names if isa.lookup(n) is None] == []


def test_simple_body_with_a_resolved_call_and_string():
    ins = decode('72 01000070  28 0100000a  2a')
    assert [(i.offset, i.opcode, i.text) for i in ins] == [
        (0, 'ldstr', '"hi \\"there\\"\\n"'),
        (5, 'call', 'void [mscorlib]System.Console::WriteLine(string)'),
        (10, 'ret', ''),
    ]


def test_branch_targets_are_relative_to_the_next_instruction():
    # IL_0000 br.s +1 -> IL_0003 ; IL_0002 nop ; IL_0003 br.s -5 -> IL_0000
    ins = decode('2b 01  00  2b fb')
    assert [i.text for i in ins] == ['IL_0003', '', 'IL_0000']


def test_long_branch():
    ins = decode('38 00000000  2a')
    assert ins[0].opcode == 'br' and ins[0].text == 'IL_0005'


def test_switch_table():
    # switch with 2 targets, relative to the end of the table (offset 13)
    ins = decode('45 02000000 00000000 02000000  00 00  2a')
    assert ins[0].operand == [13, 15]
    assert ins[0].text == '(IL_000d, IL_000f)'


def test_two_byte_opcodes():
    ins = decode('fe01  fe0c 0300  fe16 03000001')
    assert [(i.opcode, i.text) for i in ins] == [
        ('ceq', ''), ('ldloc', '3'), ('constrained.', '[mscorlib]System.Int32')]


def test_numeric_operands():
    ins = decode('1f ff  20 39050000  21 0100000000000000  22 0000803f')
    assert [i.operand for i in ins] == [-1, 1337, 1, 1.0]


def test_unresolvable_tokens_render_as_raw_tokens():
    ins = decode('28 99000006', resolver=None)
    assert ins[0].text == '/* 0x06000099 */'


def test_resolver_exceptions_fall_back_to_raw_tokens():
    class Broken:
        def method(self, tok):
            raise RuntimeError('boom')
    assert decode('28 01000006', Broken())[0].text == '/* 0x06000001 */'


@pytest.mark.parametrize('hexstr,message', [
    ('24', 'unknown opcode 0x24'),                 # 0x24 is unassigned
    ('20 0102', 'truncated operand'),
    ('fe', 'truncated two-byte opcode'),
    ('45 ffff0000', 'implausible switch'),
])
def test_bad_bytes_raise_decode_errors(hexstr, message):
    with pytest.raises(d.DecodeError, match=message):
        decode(hexstr)


def test_render_produces_ildasm_layout_the_text_parser_reads():
    from annotator.cil.parser import parse
    text = '\n'.join(d.render(decode('72 01000070  28 0100000a  2a')))
    lines, _ = parse(text)
    ops = [l for l in lines if l.kind == 'instruction']
    assert [l.mnemonic for l in ops] == ['ldstr', 'call', 'ret']
    assert ops[1].operands[0].kind == 'method'
