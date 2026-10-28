from annotator.cil import patterns as cp
from annotator.cil.explain import CilExplainer
from annotator.cil.parser import parse


def detect(src):
    lines, meta = parse(src)
    ex = CilExplainer(meta['locals'], meta['maxstack'])
    return cp.detect([ex.explain(l) for l in lines], lines)


def names(src):
    return {p['name'] for p in detect(src)}


def call(target):
    return f'call void {target}\n'


def test_benign_console_program_raises_no_warnings():
    src = ('ldstr "hello"\n'
           'call void [mscorlib]System.Console::WriteLine(string)\n'
           'ret')
    assert [p for p in detect(src) if p['severity'] == 'warning'] == []


def test_single_api_rules():
    assert 'Process Execution' in names(
        'call class [System]System.Diagnostics.Process '
        '[System]System.Diagnostics.Process::Start(string)')
    assert 'Base64 Decoding' in names(
        'call uint8[] [mscorlib]System.Convert::FromBase64String(string)')
    assert 'Reflective Assembly Loading' in names(
        'call class [mscorlib]System.Reflection.Assembly '
        '[mscorlib]System.Reflection.Assembly::Load(uint8[])')


def test_property_getters_match_rules_written_without_get_():
    assert 'Debugger Detection' in names(
        'call bool [mscorlib]System.Diagnostics.Debugger::get_IsAttached()')


def test_composite_needs_every_group():
    load_only = ('call class [mscorlib]System.Reflection.Assembly '
                 '[mscorlib]System.Reflection.Assembly::Load(uint8[])')
    assert 'Reflective Loader Chain' not in names(load_only)

    with_invoke = load_only + (
        '\ncallvirt instance object '
        '[mscorlib]System.Reflection.MethodBase::Invoke(object, object[])')
    assert 'Reflective Loader Chain' in names(with_invoke)


def test_composite_lines_cover_every_participating_call():
    src = ('IL_0000: call uint8[] [mscorlib]System.Convert::FromBase64String(string)\n'
           'IL_0005: call class [mscorlib]System.Reflection.Assembly '
           '[mscorlib]System.Reflection.Assembly::Load(uint8[])')
    hit = next(p for p in detect(src) if p['name'] == 'Decrypt and Load In Memory')
    assert hit['lines'] == [1, 2]


def test_results_carry_their_evidence():
    hit = next(p for p in detect(
        'call uint8[] [mscorlib]System.Convert::FromBase64String(string)')
        if p['name'] == 'Base64 Decoding')
    assert hit['evidence'] == ['System.Convert::FromBase64String']


def test_string_literals_count_as_evidence():
    assert 'Shell / Script Execution' in names('ldstr "cmd.exe"')


def test_pinvoke_declaration_is_detected():
    src = ('.method public hidebysig static pinvokeimpl("kernel32.dll" winapi) '
           'native int VirtualAlloc(native int a, native uint b) cil managed preservesig\n{\n}')
    assert 'P/Invoke Declaration' in names(src)


def test_opcode_rules():
    assert 'Indirect Call' in names('ldarg.0\ncalli void()')
    assert 'Method Pointer Taken' in names(
        'ldftn void [mscorlib]System.Console::WriteLine()')


def test_results_are_ordered_most_severe_first():
    src = ('call uint8[] [mscorlib]System.Convert::FromBase64String(string)\n'
           'call class [System]System.Diagnostics.Process '
           '[System]System.Diagnostics.Process::Start(string)\n'
           'call string [mscorlib]System.Environment::GetFolderPath(int32)')
    rank = {'warning': 0, 'notable': 1, 'info': 2}
    sev = [p['severity'] for p in detect(src)]
    assert sev == sorted(sev, key=rank.get)


def test_every_rule_has_a_description_and_valid_severity():
    for rule in cp.RULES + cp.COMBOS:
        assert rule.description.strip(), rule.id
        assert rule.severity in ('info', 'notable', 'warning'), rule.id


# ---- false positives -------------------------------------------------------
# Each of these fired a warning before the rules were narrowed. They are calls
# ordinary applications make constantly, and must not be reported as warnings.

ORDINARY = {
    'ASP.NET UseStartup': (
        'call class X [Microsoft.AspNetCore.Hosting]Microsoft.AspNetCore.Hosting.'
        'WebHostBuilderExtensions::UseStartup(class Y)'),
    'logging the machine name': (
        'call string [mscorlib]System.Environment::get_MachineName()'),
    'serializer resolving a type': (
        'call class [mscorlib]System.Type [mscorlib]System.Type::GetType(string)'),
    'a key-vault client': (
        'newobj instance void [Azure.Security.KeyVault]Azure.Security.KeyVault.'
        'Secrets.SecretClient::.ctor()'),
    'copying text to the clipboard': (
        'call void [System.Windows.Forms]System.Windows.Forms.Clipboard::SetText(string)'),
    'awaiting a delay': (
        'call class [mscorlib]System.Threading.Tasks.Task '
        '[mscorlib]System.Threading.Tasks.Task::Delay(int32)'),
}


import pytest  # noqa: E402


@pytest.mark.parametrize('label', sorted(ORDINARY))
def test_ordinary_calls_are_not_warnings(label):
    warnings = [p['name'] for p in detect(ORDINARY[label]) if p['severity'] == 'warning']
    assert warnings == [], f'{label}: {warnings}'


@pytest.mark.parametrize('literal', [
    r'"Software\\Microsoft\\Windows\\CurrentVersion\\Run"',   # ildasm escapes
    r'"Software\Microsoft\Windows\CurrentVersion\Run"',       # decompiler output
])
def test_run_key_matches_in_either_backslash_spelling(literal):
    assert 'Startup Persistence' in names(f'ldstr {literal}')


def test_wmi_query_is_still_vm_detection():
    assert 'VM / Sandbox Detection' in names(
        'newobj instance void [System.Management]System.Management.'
        'ManagementObjectSearcher::.ctor(string)')


def test_keyboard_hook_is_a_warning_but_clipboard_read_is_not():
    hook = detect('ldstr "GetAsyncKeyState"')
    read = detect('call string [System.Windows.Forms]System.Windows.Forms.'
                  'Clipboard::GetText()')
    assert any(p['name'] == 'Keyboard Capture' and p['severity'] == 'warning' for p in hook)
    assert any(p['name'] == 'Clipboard Read' and p['severity'] == 'notable' for p in read)


# ---- obfuscation in IL -----------------------------------------------------

def _rlo_name(n):
    """An invisible name, built from code points so nothing upstream rewrites it."""
    return ''.join(chr(c) for c in (0x202E, 0x200B, 0x206D, 0x200C)[:n])


FLATTENED_IL = f"""IL_0000:  ldc.i4     -852740963
IL_0005:  ldc.i4     -1895095320
IL_000a:  xor
IL_000b:  dup
IL_000c:  stloc.0
IL_000d:  ldc.i4.s   9
IL_000f:  rem.un
IL_0010:  switch     (IL_0030, IL_0040)
IL_0030:  call       void {_rlo_name(4)}::{_rlo_name(3)}()
IL_0040:  ret"""


def test_flattening_dispatcher_is_detected_in_il():
    hit = next(p for p in detect(FLATTENED_IL) if p['name'] == 'Control-Flow Flattening')
    assert hit['severity'] == 'warning'
    assert hit['lines'] == [3, 7, 8]


def test_switch_on_a_remainder_alone_is_not_flattening():
    src = 'ldarg.0\nldc.i4.3\nrem.un\nswitch (IL_0010, IL_0020)\nret'
    assert 'Control-Flow Flattening' not in names(src)


def test_invisible_names_in_pasted_il_are_aliased_and_flagged():
    from annotator import analyse
    r = analyse(FLATTENED_IL, arch='cil')
    assert 'Obfuscated Names' in {p['name'] for p in r['patterns']}
    raws = ' '.join(a['raw'] for a in r['annotations'])
    assert 'obf_1::obf_2()' in raws
    assert chr(0x202E) not in raws
