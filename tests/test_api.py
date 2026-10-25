import json

import pytest

from app import create_app
from annotator.examples import EXAMPLES


@pytest.fixture
def client():
    app = create_app({'TESTING': True})
    return app.test_client()


def test_index_renders(client):
    r = client.get('/')
    assert r.status_code == 200
    assert b'ASM Annotator' in r.data


def test_health(client):
    body = client.get('/api/health').get_json()
    assert body['status'] == 'ok' and body['instructions'] > 200


def test_annotate_happy_path(client):
    r = client.post('/api/annotate', json={'code': 'mov eax, 1\nint 0x80'})
    assert r.status_code == 200
    body = r.get_json()
    assert body['stats']['instructions'] == 2
    assert 'exit' in body['stats']['syscalls']


def test_annotate_rejects_empty_input(client):
    assert client.post('/api/annotate', json={'code': '   '}).status_code == 400


def test_annotate_rejects_missing_body(client):
    assert client.post('/api/annotate', json={}).status_code == 400


def test_annotate_rejects_unknown_arch(client):
    r = client.post('/api/annotate', json={'code': 'nop', 'arch': 'vax'})
    assert r.status_code == 400


def test_annotate_rejects_oversized_input(client):
    r = client.post('/api/annotate', json={'code': 'nop\n' * 60000})
    assert r.status_code == 413


def test_annotate_is_not_confused_by_a_non_string_code_field(client):
    assert client.post('/api/annotate', json={'code': 12345}).status_code == 400


@pytest.mark.parametrize('example', EXAMPLES, ids=lambda e: e['id'])
def test_every_bundled_example_analyses_cleanly(client, example):
    r = client.post('/api/annotate', json={'code': example['code']})
    assert r.status_code == 200
    body = r.get_json()
    assert body['stats']['instructions'] > 0
    # Bundled examples should be fully covered by the instruction database.
    assert body['stats']['unknown_mnemonics'] == [], example['id']


def test_examples_endpoints(client):
    assert len(client.get('/api/examples').get_json()) == len(EXAMPLES)
    assert client.get('/api/examples/loop_sum').get_json()['id'] == 'loop_sum'
    assert client.get('/api/examples/nope').status_code == 404


def test_instruction_reference(client):
    body = client.get('/api/instruction/lea').get_json()
    assert body['category'] == 'data'
    assert client.get('/api/instruction/zzz').status_code == 404


def test_register_reference(client):
    body = client.get('/api/register/ecx').get_json()
    assert body['parent'] == 'rcx' and body['width'] == 32
    assert client.get('/api/register/qqq').status_code == 404


@pytest.mark.parametrize('fmt,needle', [
    ('md', b'# Assembly analysis'),
    ('txt', b'DETECTED PATTERNS'),
    ('json', b'"annotations"'),
])
def test_exports(client, fmt, needle):
    r = client.post(f'/api/export/{fmt}', json={'code': 'push ebp\nmov ebp, esp\nret'})
    assert r.status_code == 200
    assert needle in r.data
    assert 'attachment' in r.headers['Content-Disposition']


def test_export_rejects_unknown_format(client):
    assert client.post('/api/export/pdf', json={'code': 'nop'}).status_code == 400


def test_json_export_round_trips(client):
    r = client.post('/api/export/json', json={'code': 'nop'})
    assert json.loads(r.data)['stats']['instructions'] == 1


# ---- disassembly endpoint ----------------------------------------------

SHELLCODE_HEX = '31c050682f2f7368682f62696e89e3b00bcd80'


def test_disassemble_hex(client):
    r = client.post('/api/disassemble',
                    json={'hex': SHELLCODE_HEX, 'arch': 'x86', 'bits': 32})
    assert r.status_code == 200
    body = r.get_json()
    assert body['instructions'] == 7
    assert 'xor eax, eax' in body['text']


def test_disassembled_output_feeds_straight_back_into_annotate(client):
    text = client.post('/api/disassemble',
                       json={'hex': SHELLCODE_HEX, 'bits': 32}).get_json()['text']
    body = client.post('/api/annotate', json={'code': text}).get_json()
    assert body['stats']['unknown_mnemonics'] == []
    assert 'execve' in body['stats']['syscalls']


def test_disassemble_rejects_bad_hex(client):
    r = client.post('/api/disassemble', json={'hex': 'not hex at all'})
    assert r.status_code == 400
    assert 'hex' in r.get_json()['error'].lower()


def test_disassemble_rejects_empty_input(client):
    assert client.post('/api/disassemble', json={'hex': ''}).status_code == 400


def test_disassemble_honours_the_base_address(client):
    body = client.post('/api/disassemble',
                       json={'hex': SHELLCODE_HEX, 'bits': 32,
                             'base': '0x400000'}).get_json()
    assert body['text'].startswith('00400000:')


def test_disassemble_rejects_a_non_numeric_base(client):
    r = client.post('/api/disassemble', json={'hex': SHELLCODE_HEX, 'base': 'xyz'})
    assert r.status_code == 400


def test_annotate_now_returns_blocks_and_frame(client):
    body = client.post('/api/annotate', json={
        'code': 'f:\n push ebp\n mov ebp, esp\n mov eax, [ebp+8]\n pop ebp\n ret'}).get_json()
    assert body['cfg']['blocks'] and body['cfg']['block_edges'] == []
    assert body['frame']['has_frame'] is True
    assert body['stats']['blocks'] == 1


# ---- .NET assembly browsing ----------------------------------------------

def _dotnet_fixture():
    import importlib.util
    import pathlib
    spec = importlib.util.find_spec('pythonnet')
    if spec is None or spec.origin is None:
        return None
    dll = pathlib.Path(spec.origin).parent / 'runtime' / 'Python.Runtime.dll'
    return dll if dll.exists() else None


DOTNET_DLL = _dotnet_fixture()
needs_dotnet = pytest.mark.skipif(DOTNET_DLL is None, reason='needs the pythonnet wheel')


def _upload(client, data, name='x.dll'):
    import io
    return client.post('/api/dotnet/load',
                       data={'file': (io.BytesIO(data), name)},
                       content_type='multipart/form-data')


def test_dotnet_load_requires_a_file(client):
    assert client.post('/api/dotnet/load', data={},
                       content_type='multipart/form-data').status_code == 400


def test_dotnet_load_rejects_non_pe(client):
    r = _upload(client, b'\x7fELF' + b'\x00' * 64, 'a.so')
    assert r.status_code == 400
    assert 'MZ' in r.get_json()['error']


@needs_dotnet
def test_dotnet_load_then_open_a_method(client):
    r = _upload(client, DOTNET_DLL.read_bytes(), 'Python.Runtime.dll')
    assert r.status_code == 200
    body = r.get_json()
    assert body['name'] == 'Python.Runtime'
    assert body['filename'] == 'Python.Runtime.dll'

    row = next(m['id'] for m in body['methods'] if m['has_body'] and m['calls'])
    m = client.get(f'/api/dotnet/{body["sha256"]}/method/{row}')
    assert m.status_code == 200
    text = m.get_json()['text']
    # The returned IL goes straight into the normal annotate route.
    annotated = client.post('/api/annotate', json={'code': text}).get_json()
    assert annotated['meta']['arch'] == 'cil'


def test_dotnet_method_for_an_unknown_assembly_is_gone(client):
    r = client.get('/api/dotnet/' + '0' * 64 + '/method/1')
    assert r.status_code == 410


@needs_dotnet
def test_dotnet_unknown_method_row_is_404(client):
    body = _upload(client, DOTNET_DLL.read_bytes()).get_json()
    assert client.get(f'/api/dotnet/{body["sha256"]}/method/9999999').status_code == 404


def test_assembly_cache_evicts_least_recently_used(monkeypatch):
    import app as app_module

    class Fake:
        def __init__(self, blob):
            self.blob = blob

    monkeypatch.setattr(app_module.dotnet, 'Assembly', Fake)
    cache = app_module._AssemblyCache(capacity=2)
    import hashlib
    keys = [hashlib.sha256(b).hexdigest() for b in (b'a', b'b', b'c')]
    cache.add(b'a')
    cache.add(b'b')
    cache.get(keys[0])          # touch 'a' so 'b' is the oldest
    cache.add(b'c')
    assert cache.get(keys[0]) is not None
    assert cache.get(keys[1]) is None
    assert cache.get(keys[2]) is not None
