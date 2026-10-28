import pathlib
import re

import pytest

from annotator import analyse, csharp
from annotator.examples import EXAMPLES

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'confuser_antidebug.cs'
INVISIBLE = re.compile('[' + ''.join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F))
                       + chr(0x202A) + '-' + chr(0x202E) + chr(0x2060) + '-' + chr(0x206F) + ']')


def escaped(text):
    """dnSpy writes invisible name characters as backslash-u escapes."""
    return INVISIBLE.sub(lambda m: chr(92) + 'u%04X' % ord(m.group(0)), text)


@pytest.fixture(scope='module', params=['raw', 'escaped'])
def sample(request):
    text = FIXTURE.read_text()
    return analyse(escaped(text) if request.param == 'escaped' else text)


def titles(result):
    return {a['index']: a['title'] for a in result['annotations'] if a.get('title')}


# ---- the bug that was reported -----------------------------------------------

def test_decompiled_csharp_is_not_mistaken_for_x86(sample):
    # Before: routed to x86, 73 "unknown instructions", 0% recognised, no findings.
    assert sample['meta']['arch'] == 'csharp'
    assert 'not in the instruction database' not in ' '.join(titles(sample).values())


def test_every_bundled_example_still_routes_where_it_did():
    for e in EXAMPLES:
        assert analyse(e['code'])['meta']['arch'] != 'csharp', e['id']


# ---- what the sample is ------------------------------------------------------------

def test_sample_findings(sample):
    names = {p['name'] for p in sample['patterns']}
    assert {'Anti-Debug Kill Switch', 'Profiler Detection', 'Abrupt Termination',
            'Control-Flow Flattening', 'Obfuscated Names', 'Code in <Module>',
            'Reflective Invocation', 'Background Thread'} <= names


def test_invisible_names_are_aliased_and_bidi_never_reaches_output(sample):
    raw_lines = ' '.join(a['raw'] for a in sample['annotations'])
    assert 'obf_1' in raw_lines and 'obf_2' in raw_lines
    assert not INVISIBLE.search(raw_lines)
    assert chr(92) + 'u202E' not in raw_lines


def test_reflection_is_followed_through_locals(sample):
    t = titles(sample)
    assert t[38].startswith('Look up Environment.GetEnvironmentVariable by name')


def test_branch_condition_is_decoded(sample):
    # typeof -> GetMethod("...") -> Invoke, and "COR" + "_ENABLE_PROFILING", resolved.
    assert titles(sample)[48] == ('Choose the next state depending on whether '
                                  '"1".Equals(Environment.GetEnvironmentVariable('
                                  '"COR_ENABLE_PROFILING"))')


def test_states_say_when_they_run(sample):
    t = titles(sample)
    assert t[60] == 'State 5: never reached on any path — a decoy'
    assert t[62].startswith('State 6: runs only when "1".Equals(Environment.GetEnvironmentVariable')
    assert t[66] == 'State 8: runs on every path'


def test_recovered_program_is_on_the_flattening_card(sample):
    card = next(p for p in sample['patterns'] if p['id'] == 'flattening')
    steps = card['steps']
    profiler = steps.index(next(s for s in steps if 'is true:' in s and 'PROFILING' in s))
    assert steps[profiler + 3].strip() == '3. Environment.FailFast(null);'


def test_thread_target_is_named(sample):
    note = next(a for a in sample['annotations'] if a['index'] == 56)['notes']
    assert 'The thread will run <Module>.obf_2.' in note


def test_multi_line_statements_are_one_card(sample):
    by_index = {a['index']: a for a in sample['annotations']}
    assert by_index[49]['kind'] == 'blank' and by_index[50]['kind'] == 'blank'


# ---- ordinary C# ---------------------------------------------------------------------

HELLO = '''using System;

namespace Demo
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            string name = Environment.UserName;
            Console.WriteLine("Hello, " + name);
        }
    }
}
'''


def test_ordinary_csharp_has_no_warnings():
    r = analyse(HELLO)
    assert r['meta']['arch'] == 'csharp'
    assert [p['name'] for p in r['patterns'] if p['severity'] == 'warning'] == []
    assert r['deflattened'] == []


def test_typeof_reflection_inline():
    src = HELLO.replace('string name = Environment.UserName;',
                        'MethodInfo m = typeof(Assembly).GetMethod("Load");\n'
                        '            object x = m.Invoke(null, new object[] { data });')
    names = {p['name'] for p in analyse(src)['patterns']}
    assert 'Reflective Assembly Loading' in names        # Assembly::Load, found by name


def test_split_string_is_rebuilt():
    src = HELLO.replace('string name = Environment.UserName;',
                        'string a = "cmd";\n            string b = a + ".exe";')
    r = analyse(src)
    notes = ' '.join(n for a in r['annotations'] for n in a.get('notes', []))
    assert 'Builds "cmd.exe" from pieces' in notes
    assert 'Shell / Script Execution' in {p['name'] for p in r['patterns']}


def test_forcing_csharp_through_the_api():
    from app import create_app
    client = create_app({'TESTING': True}).test_client()
    r = client.post('/api/annotate', json={'code': HELLO, 'arch': 'csharp'})
    assert r.status_code == 200 and r.get_json()['meta']['arch'] == 'csharp'
