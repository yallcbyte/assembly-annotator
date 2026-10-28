import pathlib
import re

import pytest

from annotator import deobf

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'confuser_antidebug.cs'


# ---- evaluator ------------------------------------------------------------

@pytest.mark.parametrize('expr,env,value', [
    ('2 + 3 * 4', {}, 14),
    ('1 ^ 2 * 3', {}, 7),                      # * binds tighter than ^
    ('(1 ^ 2) * 3', {}, 9),
    ('4294967295U + 1U', {}, 0),               # uint32 wrap
    ('num2 * 580075008U ^ 2567525357U', {'num2': 1}, 580075008 ^ 2567525357),
    ('10 % 4 | 8', {}, 10),
    ('x & 0xF', None, None),                   # hex is not part of the grammar
])
def test_evaluate(expr, env, value):
    if env is None:
        with pytest.raises(deobf._ExprError):
            deobf.evaluate(expr, {'x': 1})
    else:
        assert deobf.evaluate(expr, env) == value


@pytest.mark.parametrize('expr', [
    "__import__('os').system('id')",
    'num.bit_length()',
    'open("x")',
    '1 +',
    '(1 + 2',
    'unknown * 2',
])
def test_evaluator_rejects_anything_but_arithmetic(expr):
    with pytest.raises(deobf._ExprError):
        deobf.evaluate(expr, {'num': 1})


# ---- names ------------------------------------------------------------------

def escaped(text):
    """dnSpy's spelling: invisible characters written as backslash-u escapes.

    Built with chr(92) so no tool along the way can turn the escapes back
    into the characters they name.
    """
    return INVISIBLE.sub(lambda m: chr(92) + 'u%04X' % ord(m.group(0)), text)


INVISIBLE = re.compile('[' + ''.join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F))
                       + chr(0x202A) + '-' + chr(0x202E) + chr(0x2060) + '-' + chr(0x206F) + ']')


def test_escaped_and_raw_spellings_share_an_alias():
    raw = 'call ' + ''.join(chr(c) for c in (0x202E, 0x200B, 0x206D)) + '()'
    esc = escaped(raw)
    assert chr(92) + 'u202E' in esc and chr(0x202E) not in esc     # really escaped
    al = deobf.NameAliaser()
    assert al.sub(esc) == al.sub(raw) == 'call obf_1()'


def test_distinct_names_get_distinct_aliases():
    al = deobf.NameAliaser()
    assert al.sub('​‌ a ‌​ a ​‌') == 'obf_1 a obf_2 a obf_1'


def test_ordinary_text_is_untouched():
    text = 'Console.WriteLine("café 日本");  // hello'
    assert deobf.NameAliaser().sub(text) == text


def test_a_single_invisible_character_is_not_a_name():
    assert deobf.NameAliaser().sub('a​b') == 'a​b'


def test_describe_classifies_characters():
    al = deobf.NameAliaser()
    al.sub('‮​')
    assert al.describe()[0]['kinds'] == ['bidi control', 'zero-width']


def test_bidi_overrides_are_made_visible():
    assert deobf.neutralise_bidi('a‮b') == 'a⟨U+202E⟩b'


# ---- flattening --------------------------------------------------------------------

@pytest.fixture(scope='module', params=['raw', 'escaped'])
def flattened(request):
    text = FIXTURE.read_text()
    if request.param == 'escaped':
        text = escaped(text)
        assert chr(92) + 'u202E' in text
    lines = deobf.NameAliaser().sub(text).splitlines()
    return deobf.unflatten(lines, deobf.find_dispatchers(lines)[0])


def test_dispatcher_constants(flattened):
    assert (flattened['state_variable'], flattened['key'], flattened['modulus'],
            flattened['initial']) == ('num', 2399871976, 9, 3442226333)


def test_every_path_is_recovered(flattened):
    paths = {tuple(p['order']): [(c['condition'], c['value']) for c in p['conditions']]
             for p in flattened['paths']}
    profiling = '"1".Equals(method.Invoke(null, new object[] { str + "_ENABLE_PROFILING" }))'
    assert paths == {
        (8, 2, 0, 3, 4, 1): [('method != null', True), (profiling, False)],
        (8, 2, 0, 3, 6, 4, 1): [('method != null', True), (profiling, True)],
        (8, 2, 0, 4, 1): [('method != null', False)],
    }
    assert all(p['end'] == 'exit' for p in flattened['paths'])


def test_decoy_state_is_reported(flattened):
    assert flattened['unreached'] == [5]       # `goto IL_06` is never taken


def test_case_statements_drop_dispatcher_plumbing(flattened):
    cases = flattened['cases']
    assert cases[8]['statements'] == ['Type typeFromHandle = typeof(Environment);']
    assert cases[2]['statements'] == [
        'MethodInfo method = typeFromHandle.GetMethod("GetEnvironmentVariable", '
        'new Type[] { typeof(string) });']
    assert cases[1]['statements'] == ['thread.IsBackground = true;', 'thread.Start(null);']
    assert cases[6]['statements'] == ['Environment.FailFast(null);']


def test_ordinary_switch_is_not_a_dispatcher():
    assert deobf.find_dispatchers(['switch (x % 3)', 'switch (state)']) == []


def test_state_machine_that_cycles_is_reported_as_a_loop():
    src = """uint num = 5U;
for (;;) {
switch ((num2 = (num ^ 1U)) % 2U)
{
case 0U:
num = 5U;
continue;
}
return;
}""".splitlines()
    r = deobf.unflatten(src, deobf.find_dispatchers(src)[0])
    assert r['paths'][0]['end'] == 'loop'


def test_missing_initial_state_gives_up_quietly():
    src = ['switch ((num2 = (num ^ 1U)) % 2U)', '{', 'case 0U:', 'return;', '}']
    assert deobf.unflatten(src, 0) is None
