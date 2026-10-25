from annotator.cil.parser import looks_like_cil, parse, split_locals

METHOD = """.method public hidebysig static void Main(string[] args) cil managed
{
  .entrypoint
  .maxstack  2
  .locals init ([0] string greeting, [1] int32 count)
  IL_0000:  nop
  IL_0001:  ldstr      "hello, world"
  IL_0006:  stloc.0
  IL_0007:  ldloc.0
  IL_0008:  call       void [mscorlib]System.Console::WriteLine(string)
  IL_000d:  ret
}"""


def instrs(src):
    lines, _ = parse(src)
    return [l for l in lines if l.kind == 'instruction']


def test_method_context_is_captured():
    _, meta = parse(METHOD)
    assert [m['name'] for m in meta['methods']] == ['Main']
    assert meta['maxstack'] == 2
    assert meta['arch'] == 'cil'


def test_locals_are_named_and_typed():
    _, meta = parse(METHOD)
    assert meta['locals'] == [
        {'slot': 0, 'type': 'string', 'name': 'greeting'},
        {'slot': 1, 'type': 'int32', 'name': 'count'},
    ]


def test_locals_spread_over_several_lines():
    src = """.locals init (
      [0] string a,
      [1] class [mscorlib]System.Text.StringBuilder sb
  )
  IL_0000:  ret"""
    _, meta = parse(src)
    assert [l['name'] for l in meta['locals']] == ['a', 'sb']
    lines, _ = parse(src)
    # Only the opening line is a directive; the wrapped lines fold into it.
    assert [l.kind for l in lines[:4]] == ['directive', 'blank', 'blank', 'blank']
    assert meta['locals'][1]['type'] == 'class [mscorlib]System.Text.StringBuilder'


def test_unnamed_locals_fall_back_to_their_slot():
    slots = split_locals('int32, string')
    assert [s['slot'] for s in slots] == [0, 1]


def test_offsets_become_labels_so_branches_resolve():
    ops = instrs(METHOD)
    assert ops[0].label == 'IL_0000'
    assert ops[0].address == '0000'


def test_signature_operand_is_one_operand_despite_its_commas():
    line = instrs('IL_0000: callvirt instance object '
                  '[mscorlib]System.Reflection.MethodBase::Invoke(object, object[])')[0]
    assert len(line.operands) == 1
    assert line.operands[0].kind == 'method'


def test_operand_kinds():
    kinds = {l.mnemonic: l.operands[0].kind for l in instrs(
        'IL_0000: ldstr "x"\n'
        'IL_0001: br.s IL_0000\n'
        'IL_0002: ldc.i4 42\n'
        'IL_0003: ldsfld int32 Foo::bar\n'
        'IL_0004: box [mscorlib]System.Int32\n')}
    assert kinds == {'ldstr': 'string', 'br.s': 'label', 'ldc.i4': 'immediate',
                     'ldsfld': 'field', 'box': 'type'}


def test_switch_keeps_every_target():
    line = instrs('IL_0000: switch (IL_0010, IL_0020, IL_0030)')[0]
    assert [o.text for o in line.operands] == ['IL_0010', 'IL_0020', 'IL_0030']


def test_comment_markers_inside_strings_are_kept():
    line = instrs('IL_0000: ldstr "http://example.test/a"  // fetch it')[0]
    assert line.operands[0].text == '"http://example.test/a"'
    assert line.comment == 'fetch it'


def test_body_without_offsets_still_parses():
    ops = instrs('ldarg.0\nldarg.1\nadd\nret')
    assert [o.mnemonic for o in ops] == ['ldarg.0', 'ldarg.1', 'add', 'ret']


def test_braces_and_region_keywords_are_not_instructions():
    src = '.try\n{\n  IL_0000: nop\n  IL_0001: leave.s IL_0003\n}\nfinally\n{\n  IL_0002: endfinally\n}'
    assert [o.mnemonic for o in instrs(src)] == ['nop', 'leave.s', 'endfinally']


def test_cil_detection_scores():
    assert looks_like_cil(METHOD) > 20
    assert looks_like_cil('mov eax, 1\nint 0x80') == 0
    assert looks_like_cil('push ebp\nmov ebp, esp\nret') == 0
