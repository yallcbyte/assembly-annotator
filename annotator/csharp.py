"""Decompiled C# (dnSpy / ILSpy C# view).

C# reads well on its own, so this does not translate it line by line the
way the assembly annotators do. It does what a reader cannot do at a
glance: resolve which real APIs each statement calls (following reflection
through locals), rebuild strings that were split to dodge a strings search,
flag obfuscation, and recover the real order of control-flow-flattened code.
"""

import re
from collections import Counter
from typing import Dict, List, Optional

from . import deobf
from .cil import patterns as cil_patterns
from .cil.patterns import CilContext

NAMESPACES = {
    'System': ['Environment', 'Convert', 'Activator', 'Type', 'String', 'Console', 'AppDomain',
               'BitConverter', 'Buffer', 'Array', 'Guid', 'Random', 'Exception', 'GC'],
    'System.Reflection': ['Assembly', 'MethodInfo', 'MethodBase', 'ConstructorInfo', 'FieldInfo',
                          'PropertyInfo', 'Module', 'BindingFlags'],
    'System.Reflection.Emit': ['DynamicMethod', 'ILGenerator', 'AssemblyBuilder', 'ModuleBuilder'],
    'System.Threading': ['Thread', 'ThreadStart', 'ParameterizedThreadStart', 'Timer', 'Mutex',
                         'Monitor'],
    'System.Threading.Tasks': ['Task'],
    'System.Diagnostics': ['Process', 'ProcessStartInfo', 'Debugger', 'Stopwatch', 'StackTrace'],
    'System.Net': ['WebClient', 'WebRequest', 'HttpWebRequest', 'Dns', 'ServicePointManager'],
    'System.Net.Http': ['HttpClient'],
    'System.Net.Sockets': ['Socket', 'TcpClient', 'TcpListener', 'UdpClient', 'NetworkStream'],
    'System.IO': ['File', 'Directory', 'Path', 'FileStream', 'MemoryStream', 'StreamReader',
                  'StreamWriter', 'BinaryReader'],
    'System.Text': ['Encoding', 'StringBuilder'],
    'System.Security.Cryptography': ['Aes', 'AesManaged', 'RijndaelManaged', 'TripleDES',
                                     'TripleDESCryptoServiceProvider', 'DESCryptoServiceProvider',
                                     'MD5', 'SHA1', 'SHA256', 'Rfc2898DeriveBytes', 'CryptoStream',
                                     'ProtectedData', 'RSACryptoServiceProvider'],
    'System.Runtime.InteropServices': ['Marshal', 'GCHandle'],
    'System.Management': ['ManagementObjectSearcher', 'ManagementClass', 'ManagementObject'],
    'Microsoft.Win32': ['Registry', 'RegistryKey'],
    'System.Windows.Forms': ['Clipboard'],
}
KNOWN_TYPES = {t: ns for ns, types in NAMESPACES.items() for t in types}

# Plain-English meaning of the APIs that matter most when triaging.
DESCRIBE = {
    'Environment.FailFast': 'Terminate the process immediately; finally blocks and exception '
                            'handlers do not run',
    'Environment.Exit': 'Exit the process',
    'Environment.GetEnvironmentVariable': 'Read an environment variable',
    'Environment.GetFolderPath': 'Look up a special folder path',
    'Type.GetMethod': 'Look up a method by name through reflection',
    'Type.GetType': 'Look up a type by name through reflection',
    'Type.InvokeMember': 'Call a member chosen by name at run time',
    'MethodInfo.Invoke': 'Call the method found through reflection',
    'MethodBase.Invoke': 'Call the method found through reflection',
    'Activator.CreateInstance': 'Create an object of a type chosen at run time',
    'Assembly.Load': 'Load .NET code from bytes, without it touching disk',
    'Assembly.LoadFrom': 'Load .NET code from a file',
    'Assembly.LoadFile': 'Load .NET code from a file',
    'Assembly.GetExecutingAssembly': 'Get the assembly this code is running in',
    'Assembly.GetManifestResourceStream': 'Read an embedded resource — a common place to '
                                          'hide a payload',
    'Assembly.EntryPoint': 'Get the entry point of a loaded assembly',
    'Thread.Thread': 'Create a thread',
    'Thread.Start': 'Start the thread',
    'Thread.IsBackground': 'Mark it as a background thread, so it never keeps the process alive',
    'Thread.Sleep': 'Pause the current thread',
    'Debugger.IsAttached': 'Check whether a debugger is attached',
    'Debugger.IsLogging': 'Check whether a debugger is logging',
    'Debugger.Break': 'Break into a debugger',
    'Process.Start': 'Start another program',
    'Process.GetCurrentProcess': 'Get the current process',
    'Process.Kill': 'Kill a process',
    'Convert.FromBase64String': 'Decode Base64 text into bytes',
    'Convert.ToBase64String': 'Encode bytes as Base64 text',
    'Encoding.GetString': 'Turn bytes into text',
    'Encoding.GetBytes': 'Turn text into bytes',
    'WebClient.DownloadString': 'Download a URL as text',
    'WebClient.DownloadData': 'Download a URL as bytes',
    'WebClient.DownloadFile': 'Download a URL to a file',
    'HttpClient.GetAsync': 'Request a URL',
    'HttpClient.GetStringAsync': 'Download a URL as text',
    'File.WriteAllBytes': 'Write bytes to a file',
    'File.ReadAllBytes': 'Read a whole file',
    'File.Delete': 'Delete a file',
    'File.Copy': 'Copy a file',
    'Registry.SetValue': 'Write a registry value',
    'RegistryKey.SetValue': 'Write a registry value',
    'RegistryKey.CreateSubKey': 'Create a registry key',
    'Marshal.AllocHGlobal': 'Allocate unmanaged memory',
    'Marshal.Copy': 'Copy between managed and unmanaged memory',
    'Marshal.GetDelegateForFunctionPointer': 'Turn a raw function pointer into something callable',
}

_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_USING_RE = re.compile(r'^\s*using\s+([\w.]+)\s*;')
_NAMESPACE_RE = re.compile(r'^\s*namespace\s+([\w.]+)')
_TYPE_RE = re.compile(r'^\s*(?:(?:public|private|internal|protected|static|sealed|abstract|'
                      r'partial|unsafe|readonly)\s+)*(class|struct|interface|enum)\s+([<>\w.`]+)')
_METHOD_RE = re.compile(r'^\s*(?P<mods>(?:(?:public|private|internal|protected|static|virtual|'
                        r'override|sealed|abstract|extern|unsafe|async|new)\s+)+)'
                        r'(?P<ret>[\w.<>\[\],]+)\s+(?P<name>[\w<>.`]+)\s*\((?P<params>[^)]*)\)\s*$')
_LABEL_RE = re.compile(r'^\s*([A-Za-z_]\w*)\s*:\s*$')
_DECL_RE = re.compile(r'(?<![\w.])([A-Za-z_][\w.]*(?:<[^;=()]*?>)?(?:\[\])*)\s+([A-Za-z_]\w*)\s*(?=[=;,)])')
_CALL_RE = re.compile(r'(?<![\w.])((?:[A-Za-z_<][\w<>]*\.)*[A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(')
_TYPEOF_CALL_RE = re.compile(r'typeof\(\s*([\w.]+)\s*\)\s*\.\s*([A-Za-z_]\w*)\s*\(')
_PROP_RE = re.compile(r'(?<![\w.])((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\.([A-Z]\w*)\b(?!\s*[(\w.])')
_NEW_RE = re.compile(r'\bnew\s+([A-Za-z_][\w.]*)\s*(?:<[^>]*>)?\s*\(')
_LOOKUP_RE = re.compile(r'(?:typeof\(\s*([\w.]+)\s*\)|([A-Za-z_]\w*))\s*\.\s*'
                        r'Get(?:Method|Property|Field)\s*\(\s*"([^"]+)"')
_CONCAT_RE = re.compile(r'((?:"(?:[^"\\]|\\.)*"|[A-Za-z_]\w*)(?:\s*\+\s*(?:"(?:[^"\\]|\\.)*"|[A-Za-z_]\w*))+)')
_NOT_TYPES = {'return', 'new', 'goto', 'case', 'else', 'using', 'namespace', 'class', 'struct',
              'throw', 'in', 'is', 'as', 'out', 'ref'}


def looks_like_csharp(text: str) -> float:
    score = 0.0
    score += 4 * len(re.findall(r'^\s*using\s+[\w.]+\s*;', text, re.M))
    score += 4 * len(re.findall(r'^\s*namespace\s+[\w.]+', text, re.M))
    score += 4 * len(re.findall(r'\b(?:class|struct|interface)\s+[<>\w]+\s*$', text, re.M))
    score += 3 * len(re.findall(r'^\s*(?:public|private|internal|protected)\s+[\w\s<>\[\],.]*\(',
                                text, re.M))
    score += 2 * len(re.findall(r'\btypeof\s*\(', text))
    score += 2 * len(re.findall(r'^\s*//\s*Token:\s*0x[0-9A-Fa-f]{8}', text, re.M))
    score += 2 * len(re.findall(r'\bfor\s*\(\s*;\s*;\s*\)|\bwhile\s*\(\s*true\s*\)', text))
    score += min(10, len(re.findall(r'\)\s*;\s*$', text, re.M)))
    score += min(5, 0.5 * len(re.findall(r'^\s*[{}]\s*$', text, re.M)))
    return score


def _qualify(type_name: str) -> str:
    short = type_name.split('.')[-1]
    if '.' in type_name:
        return type_name
    ns = KNOWN_TYPES.get(short)
    return f'{ns}.{short}' if ns else type_name


class Unit:
    """Everything collected about the listing before statements are annotated."""

    def __init__(self, lines: List[str]):
        joined = '\n'.join(lines)
        self.usings = [m.group(1) for l in lines for m in [_USING_RE.match(l)] if m]
        self.namespaces = set(self.usings) | {'System'}
        self.local_types: Dict[str, str] = {}
        for m in _DECL_RE.finditer(_STRING_RE.sub('""', joined)):
            if m.group(1) not in _NOT_TYPES:
                self.local_types.setdefault(m.group(2), m.group(1))
        self.string_locals: Dict[str, str] = {}
        for m in re.finditer(r'\bstring\s+([A-Za-z_]\w*)\s*=\s*("(?:[^"\\]|\\.)*")\s*;', joined):
            self.string_locals[m.group(1)] = m.group(2)[1:-1]
        # Reflection, followed through locals:
        #   t = typeof(Environment); m = t.GetMethod("GetEnvironmentVariable"); m.Invoke(...)
        self.type_locals: Dict[str, str] = {}
        for m in re.finditer(r'\b([A-Za-z_]\w*)\s*=\s*typeof\(\s*([\w.]+)\s*\)', joined):
            self.type_locals[m.group(1)] = _qualify(m.group(2))
        self.reflected: Dict[str, str] = {}
        for m in re.finditer(r'\b([A-Za-z_]\w*)\s*=\s*' + _LOOKUP_RE.pattern, joined):
            owner = _qualify(m.group(2)) if m.group(2) else self.type_locals.get(m.group(3))
            if owner:
                self.reflected[m.group(1)] = f'{owner}::{m.group(4)}'

    def resolve(self, chain: str) -> Optional[str]:
        """What type a receiver expression has, as far as text alone can tell."""
        parts = chain.split('.')
        if parts[0] in self.local_types:
            return _qualify(self.local_types[parts[0]]) if len(parts) == 1 else None
        if chain in self.namespaces:
            return None
        last = parts[-1]
        if last in KNOWN_TYPES:
            return _qualify(last)
        if last[:1].isupper() or last.startswith('<'):
            return chain
        return None

    def calls_on(self, statement: str) -> List[dict]:
        code = _STRING_RE.sub('""', statement)
        found = []
        for m in _TYPEOF_CALL_RE.finditer(code):
            found.append(('System.Type', m.group(2), 'call'))
        for m in _NEW_RE.finditer(code):
            found.append((_qualify(m.group(1)), '.ctor', 'new'))
        for m in _CALL_RE.finditer(code):
            if code[:m.start()].rstrip().endswith('typeof('):
                continue
            t = self.resolve(m.group(1))
            if t:
                found.append((t, m.group(2), 'call'))
        for m in _PROP_RE.finditer(code):
            t = self.resolve(m.group(1))
            if t and m.group(1) not in self.namespaces:
                after = code[m.end():].lstrip()
                kind = 'set' if after.startswith('=') and not after.startswith('==') else 'get'
                found.append((t, m.group(2), kind))
        for m in _LOOKUP_RE.finditer(statement):
            owner = _qualify(m.group(1)) if m.group(1) else self.type_locals.get(m.group(2))
            if owner:
                found.append((owner, m.group(3), 'lookup'))
        for m in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)\s*\.\s*Invoke\s*\(', code):
            target = self.reflected.get(m.group(1))
            if target:
                owner, member = target.split('::', 1)
                found.append((owner, member, 'reflected'))
        out, seen = [], set()
        for t, member, kind in found:
            if (t, member, kind) in seen:
                continue
            seen.add((t, member, kind))
            out.append({'target': f'{t}::{member}', 'short': f'{t.split(".")[-1]}.{member}',
                        'kind': kind})
        return out

    def strings_on(self, statement: str):
        """Literals in the statement, plus any rebuilt from `local + "literal"` pieces."""
        literals = [s[1:-1] for s in _STRING_RE.findall(statement)]
        rebuilt = []
        for m in _CONCAT_RE.finditer(statement):
            pieces = re.split(r'\s*\+\s*', m.group(1))
            values = []
            for piece in pieces:
                if piece.startswith('"'):
                    values.append(piece[1:-1])
                elif piece in self.string_locals:
                    values.append(self.string_locals[piece])
                else:
                    values = None
                    break
            # Only worth reporting when a local took part, or three or more pieces did.
            if values and (any(not x.startswith('"') for x in pieces) or len(pieces) > 2):
                rebuilt.append(''.join(values))
        return literals, rebuilt


def _statements(lines):
    """Group lines into statements: a line that starts inside open brackets
    continues the statement above it (argument lists, array initialisers)."""
    depth, start, text, cont = 0, None, {}, set()
    for i, line in enumerate(lines):
        code = re.sub(r'//.*$', '', _STRING_RE.sub('""', line))
        if depth > 0 and start is not None:
            cont.add(i)
            text[start] += ' ' + line.strip()
        else:
            start = i
            text[i] = line.strip()
        depth = max(0, depth + code.count('(') + code.count('[') - code.count(')') - code.count(']'))
    for k in text:
        t = re.sub(r'\s+', ' ', text[k])
        text[k] = re.sub(r'\[\s+', '[', re.sub(r'\s+\]', ']', t))
    return {'text': text, 'continuation': cont}


def analyse(code: str, verbosity: str = 'normal') -> dict:
    aliaser = deobf.NameAliaser()
    lines = aliaser.sub(code).splitlines()
    unit = Unit(lines)

    flattened = [r for r in (deobf.unflatten(lines, i) for i in deobf.find_dispatchers(lines)) if r]
    case_info, transition_lines, dispatcher_lines = {}, set(), {}
    for f in flattened:
        dispatcher_lines[f['line']] = f
        for state, case in f['cases'].items():
            case_info[case['line']] = (f, state)
        sv = re.escape(f['state_variable'])
        for i in range(f['line'], min(len(lines), f['line'] + 400)):
            if re.match(rf'^\s*{sv}\s*=\s*', lines[i]):
                transition_lines.add(i)

    statements = _statements(lines)
    ctx = {'unit': unit, 'aliaser': aliaser, 'case_info': case_info, 'flattened': flattened,
           'transitions': transition_lines, 'dispatchers': dispatcher_lines}
    annotations, rule_inputs = [], []
    for n, raw in enumerate(lines, start=1):
        if n - 1 in statements['continuation']:
            annotations.append(_blank(n, raw))
            continue
        full = statements['text'].get(n - 1, raw.strip())
        a = _annotate(n, raw, full, ctx)
        for c in a.pop('_calls', []):
            rule_inputs.append((n, c['target']))
        if a['kind'] not in ('comment', 'blank'):
            literals, rebuilt = unit.strings_on(full)
            rule_inputs.extend((n, s) for s in literals + rebuilt)
            if rebuilt:
                a['notes'].append('Builds ' + ', '.join(f'"{r}"' for r in rebuilt)
                                  + ' from pieces — splitting a string keeps it out of a '
                                    'simple strings search.')
        a['raw'] = deobf.neutralise_bidi(a['raw'])
        annotations.append(a)

    detected = cil_patterns.run_rules(CilContext.from_parts(rule_inputs, [], []))
    detected += _obfuscation_findings(aliaser, lines, flattened, annotations, unit)
    order = {'warning': 0, 'notable': 1, 'info': 2}
    detected.sort(key=lambda r: (order.get(r['severity'], 3), r['name']))

    stmts = [a for a in annotations if a['kind'] == 'instruction']
    methods = [a for a in annotations if a.get('method_name')]
    categories = Counter(a['category'] for a in stmts)
    return {
        'meta': {
            'arch': 'csharp', 'syntax': 'decompiled', 'total_lines': len(lines),
            'instruction_count': len(stmts), 'label_count': len(methods),
            'notice': ('Decompiled C#: calls are resolved from the source text. For '
                       'instruction-by-instruction annotation, switch dnSpy to its IL view, '
                       'or drop the .dll on the Bytes tab.'),
            'aliases': aliaser.describe(),
        },
        'annotations': annotations,
        'patterns': detected,
        'cfg': {'labels': {}, 'edges': [], 'loop_headers': [], 'unreachable': [],
                'functions': [], 'blocks': [], 'block_edges': []},
        'frame': None,
        'deflattened': flattened,
        'stats': {
            'instructions': len(stmts), 'lines': len(lines), 'labels': len(methods),
            'branches': 0, 'loops': sum(1 for a in annotations if a.get('loop_header')),
            'functions': len(methods), 'blocks': 0, 'coverage': None,
            'unknown_mnemonics': [], 'syscalls': [],
            'calls': sum(1 for x in rule_inputs if '::' in x[1]),
            'methods': [m['method_name'] for m in methods],
            'categories': [{'id': c, 'label': c.title(), 'colour': '#90a4ae', 'count': k}
                           for c, k in categories.most_common()],
            'top_mnemonics': [],
            'warnings': [p['name'] for p in detected if p['severity'] == 'warning'],
        },
    }


def _blank(n, raw):
    return {'index': n, 'raw': deobf.neutralise_bidi(raw.rstrip()), 'kind': 'blank',
            'category': 'other', 'title': '', 'notes': []}


def _annotate(n, raw, full, ctx) -> dict:
    unit, aliaser = ctx['unit'], ctx['aliaser']
    a = {'index': n, 'raw': raw.rstrip(), 'kind': 'instruction', 'mnemonic': None,
         'category': 'other', 'title': '', 'detail': '', 'notes': [], 'flags': '',
         'label': None, 'comment': None, 'address': None, 'operands': [], '_calls': []}
    body = raw.strip()
    i = n - 1

    if not body or body in ('{', '}', '};'):
        a['kind'] = 'blank'
        return a
    if body.startswith('//'):
        a.update(kind='comment', category='comment')
        tok = re.match(r'//\s*Token:\s*(0x[0-9A-Fa-f]+)(?:.*?RVA:\s*(0x[0-9A-Fa-f]+))?', body)
        if tok:
            a['title'] = f'Metadata for the next line: token {tok.group(1)}' + (
                f', code at RVA {tok.group(2)}' if tok.group(2) else '')
            a['detail'] = 'dnSpy writes these; the token identifies the item inside the assembly.'
        else:
            a['title'] = 'Author’s comment'
            a['detail'] = body.lstrip('/ ')
        return a

    m = _USING_RE.match(raw)
    if m:
        a.update(kind='directive', category='directive', title=f'Imports the {m.group(1)} namespace')
        return a
    m = _NAMESPACE_RE.match(raw)
    if m:
        a.update(kind='directive', category='directive', title=f'Namespace {m.group(1)}')
        return a
    m = _TYPE_RE.match(raw)
    if m:
        kind, name = m.groups()
        a.update(kind='label', category='label', label=name, title=f'{kind.title()} {name}')
        if name == '<Module>':
            a['title'] = 'The <Module> type'
            a['notes'].append('Its static constructor runs as soon as the assembly loads, before '
                              'Main or anything else. Protections and loaders hide here.')
        _note_alias(a, name, aliaser)
        return a
    m = _METHOD_RE.match(raw)
    if m and not body.endswith(';'):
        name, params = m.group('name'), m.group('params').strip()
        a.update(kind='label', category='label', label=name, method_name=name,
                 title=f'Method {name}({params}) — {" ".join(m.group("mods").split())}, '
                       f'returns {m.group("ret")}')
        _note_alias(a, name, aliaser)
        return a
    m = _LABEL_RE.match(raw)
    if m:
        a.update(kind='label', category='label', label=m.group(1),
                 title=f'Label {m.group(1)} — a target for goto')
        return a

    calls = unit.calls_on(full)
    a['_calls'] = calls
    code = _STRING_RE.sub('""', full)

    if i in ctx['case_info']:
        f, state = ctx['case_info'][i]
        a['category'] = 'control'
        a['title'] = f'State {state}: {_when_state_runs(f, state, unit)}'
        if f['cases'][state]['statements']:
            a['detail'] = 'Does: ' + ' '.join(f['cases'][state]['statements'])
        return a
    if i in ctx['dispatchers']:
        f = ctx['dispatchers'][i]
        a.update(category='control', loop_header=True, title='Control-flow flattening dispatcher')
        a['detail'] = ('The real order is hidden behind a state variable: each case sets the '
                       'next state with scrambled arithmetic, then loops back here.')
        for k, path in enumerate(f['paths'][:4], start=1):
            cond = '; '.join(f'{readable(c["condition"], unit)} is '
                             f'{"true" if c["value"] else "false"}' for c in path['conditions'])
            a['notes'].append(f'Order {k}: ' + ' → '.join(str(s) for s in path['order'])
                              + (f'  (when {cond})' if cond else ''))
        if f['unreached']:
            a['notes'].append('Decoy states, never reached: '
                              + ', '.join(str(s) for s in f['unreached']))
        return a
    if i in ctx['transitions']:
        a.update(category='control', title='Choose the next state (scrambled arithmetic)')
        cond = _branch_condition(full, unit)
        if cond:
            a['title'] = f'Choose the next state depending on whether {cond}'
        for c in calls:
            if c['kind'] in ('reflected', 'lookup'):
                a['notes'].append(_call_sentence(c))
        return a

    if re.match(r'^(?:for\s*\(\s*;\s*;\s*\)|while\s*\(\s*true\s*\))', code):
        a.update(category='control', loop_header=True, title='Loop forever')
        if ctx['flattened']:
            a['detail'] = 'In flattened code this loop only drives the dispatcher.'
        return a
    if code.startswith('continue'):
        a.update(category='control',
                 title='Back to the dispatcher' if ctx['flattened'] else 'Next loop iteration')
        return a
    m = re.match(r'^goto\s+(\w+)\s*;', code)
    if m:
        a.update(category='control', title=f'Jump to label {m.group(1)}')
        return a
    if re.match(r'^return\b', code):
        a.update(category='control', title='Return')
        return a

    if calls:
        special = [c for c in calls if c['kind'] in ('reflected', 'lookup')]
        known = [c for c in calls if _describe_key(c) in DESCRIBE]
        lead = (special or known or calls)[0]
        a['category'] = 'object' if lead['kind'] == 'new' else 'call'
        a['title'] = _call_sentence(lead)
        for c in calls:
            if c is lead:
                continue
            if lead['kind'] == 'lookup' and re.match(r'^Type\.Get(?:Method|Property|Field)$', c['short']):
                continue
            if c['kind'] in ('reflected', 'lookup') or _describe_key(c) in DESCRIBE:
                a['notes'].append(_call_sentence(c))
        target = re.search(r'new\s+(?:Parameterized)?ThreadStart\s*\(\s*([\w<>.]+)\s*\)', full)
        if target:
            a['notes'].append(f'The thread will run {target.group(1)}.')
        a['call'] = {'target': lead['target'], 'short': lead['short'], 'assembly': None,
                     'returns': '', 'params': [], 'instance': False, 'opcode': lead['kind']}
        return a

    m = re.match(r'^(?:[\w.<>\[\]]+\s+)?([A-Za-z_]\w*)\s*=\s*("(?:[^"\\]|\\.)*")\s*;$', full)
    if m:
        a.update(category='store', title=f'Store the string {m.group(2)} in {m.group(1)}')
        return a
    m = re.match(r'^(?:[\w.<>\[\]]+\s+)?([A-Za-z_]\w*)\s*=\s*typeof\(\s*([\w.]+)\s*\)\s*;$', full)
    if m:
        a.update(category='store', title=f'Store the type {m.group(2)} in {m.group(1)}')
        return a
    m = re.match(r'^([\w.<>\[\]]+)\s+([A-Za-z_]\w*)\s*;$', full)
    if m:
        a.update(category='store', title=f'Declare {m.group(2)} as {m.group(1)}')
        return a
    m = re.match(r'^(?:[\w.<>\[\]]+\s+)?([A-Za-z_][\w.]*)\s*=\s*(.+?);$', full)
    if m:
        if any(f['state_variable'] == m.group(1) for f in ctx['flattened']):
            a.update(category='control', title='Set the dispatcher’s starting state')
        else:
            a.update(category='store', title=f'Set {m.group(1)}')
        return a
    if re.match(r'^(?:if|else|switch|while|for|foreach)\b', code):
        a.update(category='control', title=f'{re.split(r"[ (]", code)[0].title()} statement')
        return a
    a['title'] = 'Statement'
    return a


def _describe_key(c) -> str:
    owner, member = c['short'].split('.')[0], c['short'].split('.')[-1]
    return f'{owner}.{owner}' if c['kind'] == 'new' else f'{owner}.{member}'


def _call_sentence(c) -> str:
    owner, member = c['short'].split('.')[0], c['short'].split('.')[-1]
    if c['kind'] == 'lookup':
        return (f'Look up {owner}.{member} by name through reflection — as a string, the call '
                f'never appears in the method’s call table')
    if c['kind'] == 'reflected':
        return f'Call {owner}.{member} through reflection'
    if c['kind'] == 'new':
        return DESCRIBE.get(f'{owner}.{owner}', f'Create a new {owner}')
    text = DESCRIBE.get(f'{owner}.{member}')
    if text:
        return f'{text} ({owner}.{member})'
    return f'{ {"get": "Read", "set": "Set"}.get(c["kind"], "Call") } {owner}.{member}'.strip()


def _branch_condition(statement: str, unit) -> Optional[str]:
    """The condition inside `state = ((cond) ? A : B) ^ ...`, made readable."""
    eq = statement.find('=')
    if eq < 0:
        return None
    try:
        _, ternaries = deobf._split_ternaries(statement[eq + 1:].rstrip(';'))
    except deobf._ExprError:
        return None
    if not ternaries:
        return None
    return readable(ternaries[0]['cond'], unit)


def readable(cond: str, unit) -> str:
    """Name reflected calls and rebuild split strings inside a condition."""
    for var, target in unit.reflected.items():
        owner, member = target.split('::', 1)
        cond = re.sub(rf'\b{re.escape(var)}\.Invoke\(\s*null\s*,\s*new object\[\]\s*\{{\s*(.+?)\s*\}}\s*\)',
                      lambda m: f'{owner.split(".")[-1]}.{member}({m.group(1)})', cond)
    for var, value in unit.string_locals.items():
        cond = re.sub(rf'\b{re.escape(var)}\s*\+\s*"([^"]*)"',
                      lambda m: f'"{value}{m.group(1)}"', cond)
    return cond


def _when_state_runs(f, state, unit=None) -> str:
    if state in f['unreached']:
        return 'never reached on any path — a decoy'
    with_state = [p for p in f['paths'] if state in p['order']]
    without = [p for p in f['paths'] if state not in p['order']]
    if not without:
        return 'runs on every path'
    for c in with_state[0]['conditions']:
        key = (c['state'], c['condition'], c['value'])
        in_all = all(any((d['state'], d['condition'], d['value']) == key for d in p['conditions'])
                     for p in with_state)
        in_none = all(not any((d['state'], d['condition'], d['value']) == key
                              for d in p['conditions']) for p in without)
        if in_all and in_none:
            cond = readable(c['condition'], unit) if unit else c['condition']
            return f'runs only when {cond} is {"true" if c["value"] else "false"}'
    return 'runs on some paths only'


def _note_alias(a, name, aliaser):
    for d in aliaser.describe():
        if re.search(rf'\b{d["alias"]}\b', name):
            a['notes'].append(f'{d["alias"]} stands for a name made of {d["length"]} invisible '
                              f'characters ({", ".join(d["kinds"])}).')


def _obfuscation_findings(aliaser, lines, flattened, annotations, unit=None) -> List[dict]:
    out = []
    described = aliaser.describe()
    if described:
        hit_lines = sorted({n for n, l in enumerate(lines, start=1) if re.search(r'\bobf_\d+\b', l)})
        out.append({
            'id': 'invisible_names', 'name': 'Obfuscated Names', 'severity': 'warning',
            'category': 'obfuscation',
            'description': ('Names made of invisible Unicode — zero-width spaces and '
                            'right-to-left overrides. ConfuserEx-style obfuscators rename '
                            'everything this way, so names carry no meaning and text can '
                            'display in a misleading order. Shown here as obf_1, obf_2 …'),
            'lines': hit_lines[:40], 'count': len(hit_lines),
            'evidence': [f'{d["alias"]}: {d["length"]} chars' for d in described[:6]],
        })
    for f in flattened:
        out.append({
            'id': 'flattening', 'name': 'Control-Flow Flattening', 'severity': 'warning',
            'category': 'obfuscation',
            'description': ('The statements are split into the cases of a switch inside an '
                            'endless loop, so the order on screen is not the order they run '
                            'in. The real order, recovered from the state arithmetic:'),
            'lines': [f['line'] + 1] + sorted(c['line'] + 1 for c in f['cases'].values())[:20],
            'count': len(f['cases']),
            'evidence': [f'{len(f["cases"])} states', f'{len(f["paths"])} possible orders',
                         f'{len(f["unreached"])} decoy' + ('' if len(f['unreached']) == 1 else 's')],
            'steps': _describe_paths(f, unit),
        })
    module_type = next((a for a in annotations if a.get('label') == '<Module>'), None)
    if module_type:
        out.append({
            'id': 'module_initializer', 'name': 'Code in <Module>', 'severity': 'notable',
            'category': 'execution',
            'description': ('Methods on the <Module> type. Its static constructor runs as soon '
                            'as the assembly loads, before Main or anything else, which is why '
                            'protections and loaders put their first move here.'),
            'lines': [module_type['index']], 'count': 1, 'evidence': ['<Module>'],
        })
    return out


def _describe_paths(f, unit=None) -> List[str]:
    steps = []
    for p in f['paths'][:3]:
        if p['conditions']:
            steps.append('When ' + ' and '.join(
                f'{readable(c["condition"], unit) if unit else c["condition"]} is '
                f'{"true" if c["value"] else "false"}' for c in p['conditions']) + ':')
        else:
            steps.append('Always:')
        k = 0
        for state in p['order']:
            for stmt in f['cases'][state]['statements']:
                k += 1
                steps.append(f'  {k}. {stmt}')
        if p['end'] == 'loop':
            steps.append('  … then repeats')
    return steps
