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
