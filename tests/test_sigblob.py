import pytest

from annotator.cil import sigblob as s

NAMES = {(1, 5): '[mscorlib]System.Collections.Generic.List`1',
         (1, 9): '[System]System.Net.WebClient',
         (0, 2): 'Program'}


def tn(tag, row):
    return NAMES.get((tag, row), f'T{tag}_{row}')


def b(hexstr):
    return bytes.fromhex(hexstr.replace(' ', ''))


@pytest.mark.parametrize('raw,value', [
    ('03', 3), ('7f', 0x7F), ('8080', 0x80), ('bfff', 0x3FFF), ('c0004000', 0x4000),
])
def test_compressed_integers(raw, value):
    assert s.Reader(b(raw), tn).compressed() == value


def test_instance_method_signature():
    sig = s.method(b('20 01 01 1d 05'), tn)
    assert sig == s.MethodSig(True, 'void', ['uint8[]'], 0)


def test_static_method_with_several_parameters():
    assert s.method(b('00 02 0e 0e 08'), tn).params == ['string', 'int32']


def test_class_and_valuetype_references():
    assert s.field(b('06 12 25'), tn) == 'class [System]System.Net.WebClient'
    assert s.field(b('06 11 08'), tn) == 'valuetype Program'


def test_generic_instance_args_are_bare_tokens():
    assert s.type_spec(b('15 12 15 01 0e'), tn) == \
        'class [mscorlib]System.Collections.Generic.List`1<string>'
    # a class argument is written without its `class` prefix
    assert s.type_spec(b('15 12 15 01 12 25'), tn) == \
        'class [mscorlib]System.Collections.Generic.List`1<[System]System.Net.WebClient>'


def test_native_int_inside_generic_args_is_nint():
    assert s.type_spec(b('15 12 15 01 18'), tn).endswith('List`1<nint>')


def test_byref_pointer_and_generic_parameters():
    assert s.method(b('00 03 01 10 08 0f 05 1e 00'), tn).params == ['int32&', 'uint8*', '!!0']


def test_function_pointer_is_one_token():
    # fnptr: default conv, 1 param, returns native int, takes int32
    assert s.field(b('06 1b 00 01 18 08'), tn) == 'delegate*<int32,nint>'


def test_custom_modifiers_are_skipped():
    # cmod_opt TypeRef#9 then int32
    assert s.field(b('06 20 25 08'), tn) == 'int32'


def test_locals_signature():
    assert s.locals_sig(b('07 03 0e 08 1d 1c'), tn) == ['string', 'int32', 'object[]']


def test_method_instantiation():
    assert s.method_spec(b('0a 02 0e 08'), tn) == ['string', 'int32']


def test_generic_method_definition_counts_its_parameters():
    assert s.method(b('30 01 01 01 1e 00'), tn).generic_params == 1


@pytest.mark.parametrize('raw,message', [
    ('20 01', 'ended early'),
    ('00 00 ee', 'unknown element type'),
    ('07 ff ff', 'bad compressed integer|implausible'),
    ('06', 'ended early'),
])
def test_malformed_blobs_raise(raw, message):
    with pytest.raises(s.SigError, match=message):
        if raw.startswith('07'):
            s.locals_sig(b(raw), tn)
        elif raw.startswith('06'):
            s.field(b(raw), tn)
        else:
            s.method(b(raw), tn)


def test_pathological_nesting_is_refused():
    with pytest.raises(s.SigError, match='nests too deeply'):
        s.field(b('06' + '1d' * 60 + '08'), tn)


def test_wrong_signature_kind_is_refused():
    with pytest.raises(s.SigError, match='not a field'):
        s.field(b('00 00 01'), tn)
