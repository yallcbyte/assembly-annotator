from annotator.cil.explain import CilExplainer
from annotator.cil.parser import parse


def run(src):
    lines, meta = parse(src)
    ex = CilExplainer(meta['locals'], meta['maxstack'])
    anns = [ex.explain(l) for l in lines]
    return [a for a in anns if a['kind'] == 'instruction'], ex


def titles(src):
    return [a['title'] for a in run(src)[0]]


def test_literal_is_named_at_the_call_that_consumes_it():
    t = titles('ldstr "hello"\n'
               'call void [mscorlib]System.Console::WriteLine(string)')
    assert t[1] == 'Call Console.WriteLine("hello")'


def test_literal_survives_a_round_trip_through_a_local():
    src = """.locals init ([0] string msg)
  IL_0000: ldstr "hello"
  IL_0005: stloc.0
  IL_0006: ldloc.0
  IL_0007: call void [mscorlib]System.Console::WriteLine(string)"""
    t = titles(src)
    assert t[1] == 'Store "hello" into local msg (V_0)'
    assert t[2] == 'Push local msg (V_0), currently "hello"'
    assert t[3] == 'Call Console.WriteLine("hello")'


def test_instance_call_separates_receiver_from_arguments():
    src = """IL_0000: newobj instance void [mscorlib]System.Text.StringBuilder::.ctor()
  IL_0005: ldstr "abc"
  IL_000a: callvirt instance class [mscorlib]System.Text.StringBuilder [mscorlib]System.Text.StringBuilder::Append(string)"""
    t = titles(src)
    assert t[0] == 'Create a new StringBuilder'
    assert t[2] == 'Call StringBuilder.Append on a StringBuilder, passing "abc"'


def test_return_value_feeds_the_next_call():
    t = titles('call string [mscorlib]System.Environment::get_UserName()\n'
               'call void [mscorlib]System.Console::WriteLine(string)')
    assert t[0] == 'Read Environment.UserName'
    assert t[1] == 'Call Console.WriteLine(Environment.UserName)'


def test_stack_depth_is_tracked():
    anns, ex = run('ldc.i4.1\nldc.i4.2\nadd\npop')
    assert [a['stack_after'] for a in anns] == [1, 2, 1, 0]
    assert ex.max_seen == 2


def test_void_call_leaves_nothing_behind():
    anns, _ = run('ldstr "x"\ncall void [mscorlib]System.Console::WriteLine(string)')
    assert anns[-1]['stack_after'] == 0


def test_underflow_on_a_fragment_does_not_crash():
    anns, ex = run('call void [mscorlib]System.Console::WriteLine(string)\nadd')
    assert ex.underflowed is True
    assert anns[0]['title'] == 'Call Console.WriteLine(a value)'


def test_call_carries_structured_target_info():
    anns, _ = run('ldstr "x"\ncall void [mscorlib]System.Console::WriteLine(string)')
    call = anns[1]['call']
    assert call['target'] == 'System.Console::WriteLine'
    assert call['assembly'] == 'mscorlib'
    assert call['params'] == ['string']
    assert call['opcode'] == 'call'


def test_callvirt_and_call_are_explained_differently():
    a = run('ldarg.0\ncallvirt instance string [mscorlib]System.Object::ToString()')[0][1]
    b = run('ldarg.0\ncall instance string [mscorlib]System.Object::ToString()')[0][1]
    assert any('Virtual dispatch' in n for n in a['notes'])
    assert any('non-virtual' in n for n in b['notes'])


def test_branch_names_the_value_it_tests():
    t = titles('ldc.i4.0\nbrfalse.s IL_0010')
    assert t[1] == 'Jump to IL_0010 if 0 is zero or null'


def test_two_operand_branch_names_both_sides():
    t = titles('ldarg.1\nldc.i4.5\nblt.s IL_0020')
    assert t[2] == 'Jump to IL_0020 if argument 1 is less than 5'


def test_ldarg_0_is_this():
    assert titles('ldarg.0\nret')[1] == 'Return this to the caller'


def test_type_test_uses_the_short_type_name():
    t = titles('ldarg.1\nisinst [mscorlib]System.String')
    assert t[1] == 'Test whether argument 1 is a String, pushing null if not'


def test_locals_reads_and_writes_are_recorded():
    _, ex = run('.locals init ([0] int32 n)\nIL_0000: ldc.i4.1\nIL_0001: stloc.0\nIL_0002: ldloc.0')
    assert ex.local_writes == {0: [3]}
    assert ex.local_reads == {0: [4]}


def test_new_method_resets_the_stack():
    src = ('.method static void A() cil managed\n{\n  ldc.i4.1\n}\n'
           '.method static void B() cil managed\n{\n  ret\n}')
    anns, _ = run(src)
    assert anns[-1]['stack_before'] == 0


def test_unknown_opcode_is_reported_not_fatal():
    anns, _ = run('frobnicate\nret')
    assert 'not in the CIL opcode table' in anns[0]['title']


def test_instance_property_read_and_write():
    t = titles('newobj instance void [System]System.Net.WebClient::.ctor()\n'
               'ldstr "agent"\n'
               'callvirt instance void [System]System.Net.WebClient::set_BaseAddress(string)\n'
               'newobj instance void [System]System.Net.WebClient::.ctor()\n'
               'callvirt instance string [System]System.Net.WebClient::get_BaseAddress()')
    assert t[2] == 'Set BaseAddress on a WebClient to "agent"'
    assert t[4] == 'Read BaseAddress from a WebClient'


def test_cil_blocks_split_only_at_branches_and_targets():
    # Every CIL line carries an IL_ label; those must not each become a block.
    from annotator import analyse
    from annotator.examples import BY_ID
    r = analyse(BY_ID['cil_loop']['code'])
    blocks = r['cfg']['blocks']
    assert [b['label'] for b in blocks] == ['IL_0000', 'IL_0006', 'IL_0010', 'IL_0016']
    loop = [b for b in blocks if b['loop_header']]
    assert [b['label'] for b in loop] == ['IL_0006']
    kinds = sorted((e['from'], e['to'], e['kind']) for e in r['cfg']['block_edges'])
    assert kinds == [(0, 2, 'jump'), (1, 2, 'fallthrough'),
                     (2, 1, 'taken'), (2, 3, 'fallthrough')]


def test_decoder_comments_are_explained_not_called_author_comments():
    from annotator.cil.parser import parse
    from annotator.cil.explain import CilExplainer
    src = ('// Python.Runtime.Foo::Bar   (token 0x060000fd)\n'
           '// .try IL_004d to IL_00b7 catch [netstandard]System.Exception handler IL_00b7 to IL_00c0\n'
           '// just a note')
    lines, meta = parse(src)
    ex = CilExplainer()
    t = [ex.explain(l)['title'] for l in lines]
    assert t[0] == 'Decoded from the assembly: Python.Runtime.Foo::Bar'
    assert t[1] == ('Protected region IL_004d–IL_00b7, with a catch Exception '
                    'handler at IL_00b7–IL_00c0')
    assert t[2] == 'Author’s comment'
