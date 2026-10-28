import importlib.util
import pathlib

import pytest

from annotator import analyse
from annotator.cil import assembly
from annotator.cil.assembly import Assembly, AssemblyError


def _fixture_dll():
    """pythonnet ships a real managed assembly. We only read the file."""
    spec = importlib.util.find_spec('pythonnet')
    if spec is None or spec.origin is None:
        return None
    dll = pathlib.Path(spec.origin).parent / 'runtime' / 'Python.Runtime.dll'
    return dll if dll.exists() else None


DLL = _fixture_dll()
needs_dll = pytest.mark.skipif(DLL is None or not assembly.AVAILABLE,
                               reason='needs dnfile and the pythonnet wheel')


@pytest.fixture(scope='module')
def asm():
    return Assembly(DLL.read_bytes())


@pytest.fixture(scope='module')
def overview(asm):
    return asm.scan()


# ---- rejecting bad input ----------------------------------------------------

@pytest.mark.skipif(not assembly.AVAILABLE, reason='needs dnfile')
def test_non_pe_input_is_rejected():
    with pytest.raises(AssemblyError, match='no MZ header'):
        Assembly(b'\x7fELF' + b'\x00' * 64)


@pytest.mark.skipif(not assembly.AVAILABLE, reason='needs dnfile')
def test_junk_behind_an_mz_header_is_rejected():
    with pytest.raises(AssemblyError, match='Could not parse'):
        Assembly(b'MZ' + b'\x00' * 200)


@pytest.mark.skipif(not assembly.AVAILABLE, reason='needs dnfile')
def test_oversized_input_is_rejected():
    with pytest.raises(AssemblyError, match='limit'):
        Assembly(b'MZ' + b'\x00' * (assembly.MAX_ASSEMBLY_BYTES + 1))


# ---- a real assembly ----------------------------------------------------------

@needs_dll
def test_identity_and_counts(overview):
    assert overview['name'] == 'Python.Runtime'
    assert overview['kind'] == 'dll'
    assert overview['counts']['methods'] == len(overview['methods']) > 1000
    assert len(overview['sha256']) == 64


@needs_dll
def test_every_method_body_decodes(overview):
    assert [m['name'] for m in overview['methods'] if m.get('decode_error')] == []


@needs_dll
def test_pinvoke_table_names_native_functions_and_dlls(overview):
    by_name = {p['name']: p['dll'] for p in overview['pinvokes']}
    assert 'dlopen' in by_name
    assert by_name['dlopen'].startswith(('libdl', '/usr/lib'))


@needs_dll
def test_findings_report_true_counts_and_evidence(overview):
    for f in overview['findings']:
        assert f['method_count'] >= len(f['methods'])
        assert f['evidence']
    names = {f['name'] for f in overview['findings']}
    # A Python<->.NET bridge really does all of these.
    assert {'P/Invoke Declaration', 'Unmanaged Memory / Marshalling'} <= names


@needs_dll
def test_methods_are_grouped_by_type(overview):
    listed = sorted(i for t in overview['types'] for i in t['methods'])
    assert listed == sorted(m['id'] for m in overview['methods'])


@needs_dll
def test_disassembled_methods_round_trip_through_the_cil_pipeline(asm, overview):
    with_body = [m for m in overview['methods'] if m['has_body']][:400]
    for m in with_body:
        result = analyse(asm.disassemble(m['id']), arch='cil')
        assert result['meta']['arch'] == 'cil'
        assert result['stats']['unknown_mnemonics'] == [], m['name']


@needs_dll
def test_disassembly_resolves_calls_and_locals(asm, overview):
    # Find a method that both calls something and declares locals.
    for m in overview['methods']:
        if not m['has_body'] or m['calls'] == 0:
            continue
        text = asm.disassemble(m['id'])
        if '.locals init' in text and 'call' in text:
            break
    else:
        pytest.fail('no suitable method found')
    assert text.startswith('// ')
    assert '.method ' in text and '.maxstack' in text
    assert '/* 0x' not in text, 'every token in the method should resolve'


@needs_dll
def test_pinvoke_method_disassembles_to_a_declaration(asm, overview):
    row = overview['pinvokes'][0]['method']
    text = asm.disassemble(row)
    assert 'pinvokeimpl(' in text
    assert 'P/Invoke into' in text


@needs_dll
def test_unknown_method_row_is_an_error(asm):
    with pytest.raises(AssemblyError, match='No such method'):
        asm.disassemble(10 ** 7)


@pytest.mark.parametrize('text,short', [
    ('valuetype Python.Runtime.NewReference', 'NewReference'),
    ('class [netstandard]System.Collections.Generic.List`1<string>', 'List<string>'),
    ('class [netstandard]System.Func`2<Python.Runtime.PendingFinalization,nint>',
     'Func<PendingFinalization,nint>'),
    ('native int', 'nint'),
    ('uint8[]', 'uint8[]'),          # array brackets are not an assembly qualifier
    ('int32[,]', 'int32[,]'),
    ('class [mscorlib]System.String[]', 'String[]'),
])
def test_short_type_names(text, short):
    assert assembly.short_type(text) == short


@needs_dll
def test_unobfuscated_assembly_raises_no_obfuscation_findings(overview):
    ids = {f['id'] for f in overview['findings']}
    assert not ids & {'flattening', 'invisible_names'}


@needs_dll
def test_call_graph_neighbourhood(asm, overview):
    # A method that both calls and is called, to exercise both directions.
    m = next(x for x in overview['methods'] if x['callers'] and x['callees'] and x['has_body'])
    n = asm.neighborhood(m['id'])
    focus = n['focus']
    keys = {x['key'] for x in n['nodes']}
    assert focus in keys
    layers = {x['key']: x['layer'] for x in n['nodes']}
    assert layers[focus] == 0
    assert any(v < 0 for v in layers.values()) and any(v > 0 for v in layers.values())
    assert all(e['from'] in keys and e['to'] in keys for e in n['edges'])
    # external APIs only appear as direct callees
    assert all(x['layer'] == 1 for x in n['nodes'] if x['kind'] == 'external')
    assert n['reachability_known'] is False      # a library has no entry point


@needs_dll
def test_callers_index_agrees_with_callees(asm, overview):
    g = asm.graph
    for caller, targets in list(g.callees.items())[:300]:
        for (key, _kind), _n in targets.items():
            if key[0] == 'm':
                assert caller in g.callers[key[1]]
