import pytest

from annotator.cil import isa


def sig(text):
    return isa.parse_signature(text)


def test_static_call_has_no_implicit_this():
    s = sig('void [mscorlib]System.Console::WriteLine(string)')
    assert s.instance is False
    assert s.arg_count == 1
    assert s.returns_value is False
    assert s.assembly == 'mscorlib'


def test_instance_call_counts_this_as_an_argument():
    s = sig('instance string [System]System.Net.WebClient::DownloadString(string)')
    assert s.instance is True
    assert s.arg_count == 2
    assert s.returns == 'string'


def test_constructor_with_no_parameters():
    s = sig('instance void [mscorlib]System.Object::.ctor()')
    assert s.method == '.ctor'
    assert s.params == ()
    assert s.arg_count == 1


def test_class_qualified_return_type_does_not_swallow_the_owner():
    s = sig('class [mscorlib]System.Reflection.Assembly '
            '[mscorlib]System.Reflection.Assembly::Load(uint8[])')
    assert s.type_name == 'System.Reflection.Assembly'
    assert s.method == 'Load'
    assert s.params == ('uint8[]',)


def test_short_and_full_names():
    s = sig('void [mscorlib]System.Console::WriteLine(string)')
    assert s.full_name == 'System.Console::WriteLine'
    assert s.short == 'Console.WriteLine'


def test_parameter_split_respects_nested_generics():
    parts = isa._split_params('class List`1<string>, int32, valuetype Pair`2<int32,int32>')
    assert parts == ('class List`1<string>', 'int32', 'valuetype Pair`2<int32,int32>')


@pytest.mark.parametrize('text', ['', 'IL_0010', '"literal"', 'int32', 'V_0'])
def test_things_that_are_not_signatures(text):
    assert sig(text) is None


@pytest.mark.parametrize('opcode', [
    'ldarg.0', 'ldarg.3', 'ldloc.2', 'stloc.1', 'ldc.i4.0', 'ldc.i4.8', 'ldc.i4.m1',
    'ldc.i4.s', 'br.s', 'brtrue.s', 'bne.un.s', 'blt.un', 'leave.s',
    'conv.i4', 'conv.ovf.u8.un', 'ldelem.ref', 'stelem.i1', 'ldind.u2', 'add.ovf.un',
])
def test_generated_opcode_families_exist(opcode):
    assert isa.lookup(opcode) is not None


def test_lookup_is_case_insensitive():
    assert isa.lookup('CALLVIRT') is isa.lookup('callvirt')


def test_stack_effects_for_simple_opcodes():
    assert (isa.lookup('add')['pop'], isa.lookup('add')['push']) == (2, 1)
    assert (isa.lookup('ldstr')['pop'], isa.lookup('ldstr')['push']) == (0, 1)
    assert (isa.lookup('stfld')['pop'], isa.lookup('stfld')['push']) == (2, 0)
    assert (isa.lookup('dup')['pop'], isa.lookup('dup')['push']) == (1, 2)


def test_call_opcodes_defer_their_stack_effect_to_the_signature():
    for op in ('call', 'callvirt', 'calli'):
        assert isa.lookup(op)['pop'] == isa.VARIES


def test_every_opcode_has_a_known_category():
    for name, entry in isa.OPCODES.items():
        assert entry['category'] in isa.CATEGORIES, name


def test_branch_set_covers_short_forms_and_leave():
    for op in ('br', 'br.s', 'brfalse.s', 'beq', 'bge.un.s', 'leave', 'leave.s'):
        assert op in isa.BRANCH_OPCODES
