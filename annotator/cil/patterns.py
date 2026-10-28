"""Pattern detection for CIL.

Native code forces you to guess what a call does. .NET metadata names it, so
detection here works on resolved API names rather than instruction shapes --
which makes it both far more precise and far easier to read.

Every entry carries its evidence: the actual APIs that matched, and where.
"""

import re
from typing import List


def _forms(target: str):
    """Lower-cased spellings of a call target to match against.

    A C# property compiles to `get_X`/`set_X` methods, so `Debugger::IsAttached`
    appears in IL as `Debugger::get_IsAttached`. Matching both spellings means
    rules can be written the way a reader would say them.
    """
    low = target.lower().replace('\\\\', '\\')
    stripped = low.replace('::get_', '::').replace('::set_', '::')
    return (low,) if stripped == low else (low, stripped)


class ApiRule:
    """Matches calls by API name, with the matched names kept as evidence."""

    def __init__(self, pid, name, description, severity='notable', category='api',
                 apis=(), opcodes=(), declarations=(), min_hits=1):
        self.id = pid
        self.name = name
        self.description = description
        self.severity = severity
        self.category = category
        self.apis = tuple(a.lower() for a in apis)
        self.opcodes = tuple(opcodes)
        self.declarations = tuple(d.lower() for d in declarations)
        self.min_hits = min_hits

    def match(self, ctx):
        lines, evidence = [], []
        for index, target in ctx.calls:
            for low in _forms(target):
                matched = next((n for n in self.apis if n in low), None)
                if matched:
                    lines.append(index)
                    evidence.append(target)
                    break
        for index, opcode in ctx.opcodes:
            if opcode in self.opcodes:
                lines.append(index)
                evidence.append(opcode)
        for index, text in ctx.declarations:
            low = text.lower()
            for needle in self.declarations:
                if needle in low:
                    lines.append(index)
                    evidence.append(needle)
                    break
        if len(set(lines)) < self.min_hits:
            return [], []
        return sorted(set(lines)), sorted(set(evidence))


class Combo:
    """Fires only when several rules all match -- the high-signal detections."""

    def __init__(self, pid, name, description, severity, category, groups):
        self.id = pid
        self.name = name
        self.description = description
        self.severity = severity
        self.category = category
        self.groups = groups   # list of tuples of API substrings

    def match(self, ctx):
        lines, evidence = [], []
        for group in self.groups:
            hit = False
            for index, target in ctx.calls:
                forms = _forms(target)
                if any(n.lower() in low for n in group for low in forms):
                    lines.append(index)
                    evidence.append(target)
                    hit = True
            if not hit:
                return [], []
        return sorted(set(lines)), sorted(set(evidence))


RULES = [
    # ---- execution -------------------------------------------------
    ApiRule('proc_start', 'Process Execution',
            'Starts another program. In a downloader or dropper this is the final '
            'step, and the arguments usually name what gets run.',
            'warning', 'execution',
            apis=['System.Diagnostics.Process::Start', 'ProcessStartInfo::',
                  'Process::GetProcesses']),
    ApiRule('shell_exec', 'Shell / Script Execution',
            'Names a command interpreter. Anything passed to it runs with this '
            'process\u2019s privileges.',
            'warning', 'execution',
            apis=['cmd.exe', 'powershell', '/bin/sh', '/bin/bash', 'wscript.shell']),

    # ---- network ----------------------------------------------------
    ApiRule('net_download', 'Network Download',
            'Fetches remote content. Combined with execution or assembly loading, '
            'this is the shape of a downloader.',
            'warning', 'network',
            apis=['WebClient::DownloadString', 'WebClient::DownloadData',
                  'WebClient::DownloadFile', 'WebClient::OpenRead',
                  'HttpClient::GetAsync', 'HttpClient::GetStringAsync',
                  'HttpClient::GetByteArrayAsync', 'WebRequest::Create',
                  'HttpWebRequest::', 'WebClient::UploadString',
                  'WebClient::UploadData']),
    ApiRule('raw_socket', 'Raw Socket Use',
            'Opens a socket directly rather than going through HTTP. Reverse shells '
            'and custom C2 protocols look like this.',
            'warning', 'network',
            apis=['Sockets.Socket::', 'TcpClient::', 'TcpListener::',
                  'NetworkStream::', 'UdpClient::']),
    ApiRule('dns', 'Host Resolution',
            'Resolves host names, often to reach a hard-coded command-and-control '
            'address.', 'notable', 'network',
            apis=['System.Net.Dns::']),

    # ---- reflection and dynamic loading --------------------------------
    ApiRule('assembly_load', 'Reflective Assembly Loading',
            'Loads .NET code at run time, frequently from a byte array that was just '
            'decrypted. The loaded assembly never touches disk, so on-disk scanning '
            'misses it entirely.',
            'warning', 'loader',
            apis=['Assembly::Load', 'Assembly::LoadFrom', 'Assembly::LoadFile',
                  'Assembly::UnsafeLoadFrom', 'AppDomain::Load']),
    ApiRule('reflection_invoke', 'Reflective Invocation',
            'Calls a method chosen at run time. Common in plugin hosts and dependency '
            'injection, so on its own it is only notable; paired with Assembly.Load it '
            'becomes the Reflective Loader Chain.',
            'notable', 'loader',
            apis=['MethodBase::Invoke', 'MethodInfo::Invoke', 'ConstructorInfo::Invoke',
                  'Type::InvokeMember', 'Activator::CreateInstance']),
    ApiRule('dynamic_code', 'Runtime Code Generation',
            'Emits IL at run time. Legitimate in serializers and ORMs, and a strong '
            'obfuscation signal everywhere else.',
            'warning', 'loader',
            apis=['DynamicMethod::', 'ILGenerator::', 'AssemblyBuilder::',
                  'ModuleBuilder::', 'CSharpCodeProvider::', 'CompileAssemblyFrom']),

    # ---- encoding and crypto ---------------------------------------------
    ApiRule('base64', 'Base64 Decoding',
            'Decodes Base64. On its own it is ordinary; feeding the result into '
            'Assembly.Load or a decryptor is not.',
            'notable', 'crypto',
            apis=['Convert::FromBase64String', 'Convert::ToBase64String']),
    ApiRule('crypto', 'Cryptography',
            'Symmetric crypto or hashing. In malware this usually unwraps a payload '
            'or a configuration blob rather than protecting user data.',
            'notable', 'crypto',
            apis=['RijndaelManaged', 'AesManaged', 'Aes::Create', 'AesCryptoServiceProvider',
                  'TripleDES', 'DESCryptoServiceProvider', 'RC2', 'CryptoStream::',
                  'Rfc2898DeriveBytes', 'MD5::', 'SHA1::', 'SHA256::',
                  'ICryptoTransform::', 'ProtectedData::Unprotect']),

    # ---- persistence and the file system -----------------------------------
    ApiRule('registry', 'Registry Access',
            'Reads or writes the Windows registry. Run keys here mean persistence.',
            'notable', 'persistence',
            apis=['Microsoft.Win32.Registry', 'RegistryKey::']),
    ApiRule('startup_persistence', 'Startup Persistence',
            'Names a Run key or the Startup folder, which makes a program survive '
            'a reboot.',
            'warning', 'persistence',
            apis=['currentversion\\run', 'start menu\\programs\\startup']),
    ApiRule('file_write', 'File System Writes',
            'Creates or modifies files. Dropping a payload looks like this.',
            'notable', 'filesystem',
            apis=['File::WriteAllBytes', 'File::WriteAllText', 'File::Copy',
                  'File::Move', 'File::Delete', 'FileStream::',
                  'Directory::CreateDirectory', 'Path::GetTempPath',
                  'Path::GetTempFileName']),
    ApiRule('scheduled_task', 'Scheduled Task / Service',
            'Registers a task or service, another way to persist across reboots.',
            'warning', 'persistence',
            apis=['TaskService', 'ServiceController::', 'schtasks']),

    # ---- anti-analysis -------------------------------------------------------
    ApiRule('anti_debug', 'Debugger Detection',
            'Checks whether a debugger is attached, and usually changes behaviour if '
            'one is.',
            'warning', 'anti-analysis',
            apis=['Debugger::IsAttached', 'Debugger::IsLogging', 'Debugger::Break',
                  'CheckRemoteDebuggerPresent', 'IsDebuggerPresent']),
    ApiRule('anti_profiler', 'Profiler Detection',
            'Checks COR_ENABLE_PROFILING, which is set when a .NET profiler or tracer is '
            'attached. Anti-analysis code reads it to notice instrumentation.',
            'warning', 'anti-analysis',
            apis=['_enable_profiling', 'cor_profiler']),
    ApiRule('fail_fast', 'Abrupt Termination',
            'Calls Environment.FailFast, which kills the process instantly without running '
            'finally blocks or exception handlers. Anti-debug code uses it to vanish the moment '
            'it notices analysis.',
            'notable', 'anti-analysis',
            apis=['Environment::FailFast']),
    ApiRule('background_thread', 'Background Thread',
            'Starts a thread that does not keep the process alive. Anti-debug protections run '
            'their debugger watchdog this way.',
            'info', 'execution',
            apis=['Thread::IsBackground']),
    ApiRule('vm_detect', 'VM / Sandbox Detection',
            'Queries WMI, the usual way to fingerprint an analysis VM and stay dormant '
            'inside one.',
            'warning', 'anti-analysis',
            apis=['ManagementObjectSearcher', 'ManagementClass::', 'ManagementObject::']),
    ApiRule('sleep_evasion', 'Execution Delay',
            'Sleeps the thread. A long delay can outlast a sandbox\u2019s analysis '
            'window; a short one is usually just polling.',
            'info', 'anti-analysis',
            apis=['Thread::Sleep']),

    # ---- native interop ------------------------------------------------------
    ApiRule('pinvoke', 'P/Invoke Declaration',
            'Declares a call into native code. This is how managed code reaches the '
            'Win32 API, including the memory and thread functions used to run '
            'shellcode.',
            'warning', 'interop',
            declarations=['pinvokeimpl']),
    ApiRule('marshal', 'Unmanaged Memory / Marshalling',
            'Moves data between managed and native memory. Allocating, copying and '
            'then calling into a buffer is the managed route to shellcode execution.',
            'warning', 'interop',
            apis=['Marshal::AllocHGlobal', 'Marshal::Copy', 'Marshal::AllocCoTaskMem',
                  'Marshal::GetDelegateForFunctionPointer', 'Marshal::StringToHGlobal',
                  'Marshal::WriteByte', 'GCHandle::Alloc', 'Marshal::UnsafeAddrOfPinnedArrayElement']),
    ApiRule('calli_indirect', 'Indirect Call',
            'Calls through a function pointer, so the target cannot be named '
            'statically.',
            'warning', 'obfuscation', opcodes=['calli']),
    ApiRule('ldftn_pointer', 'Method Pointer Taken',
            'Takes the address of a method. Normal for delegates, and also how '
            'obfuscators build indirect dispatch tables.',
            'info', 'obfuscation', opcodes=['ldftn', 'ldvirtftn']),

    # ---- data theft ------------------------------------------------------------
    ApiRule('keyboard_hook', 'Keyboard Capture',
            'Reads key state or installs an input hook \u2014 the core of a keylogger.',
            'warning', 'collection',
            apis=['GetAsyncKeyState', 'GetKeyboardState', 'SetWindowsHookEx']),
    ApiRule('clipboard_read', 'Clipboard Read',
            'Reads the clipboard. Ordinary for a paste action; a clipper reads it '
            'repeatedly to swap out copied wallet addresses.',
            'notable', 'collection',
            apis=['Clipboard::GetText', 'Clipboard::GetData', 'Clipboard::GetDataObject']),
    ApiRule('screen_capture', 'Screen Capture',
            'Takes a screenshot.', 'warning', 'collection',
            apis=['CopyFromScreen', 'Graphics::CopyFromScreen', 'BitBlt']),
    ApiRule('credential_paths', 'Credential Store Access',
            'Names a browser profile file where saved logins and cookies live.',
            'warning', 'collection',
            apis=['login data', 'logins.json', 'key4.db', 'cookies.sqlite', 'web data',
                  'CredEnumerate']),

    # ---- discovery ---------------------------------------------------------------
    ApiRule('environment_probe', 'Environment Discovery',
            'Reads machine, user and path information about the host.',
            'info', 'discovery',
            apis=['Environment::GetFolderPath', 'Environment::GetEnvironmentVariable',
                  'Environment::OSVersion', 'Environment::CurrentDirectory',
                  'Environment::MachineName', 'Environment::UserName',
                  'Environment::ProcessorCount', 'SystemInformation::']),
    ApiRule('exceptions', 'Exception Handling',
            'Uses try/catch. Heavy use around every operation can be control flow '
            'deliberately hidden inside exception handlers.',
            'info', 'structure', opcodes=['leave', 'leave.s', 'endfinally', 'rethrow']),
]


COMBOS = [
    Combo('download_exec', 'Download and Execute',
          'Remote content is fetched and then run. Taken together these two steps are '
          'the definition of a downloader, which neither call is on its own.',
          'warning', 'behaviour',
          [('WebClient::Download', 'HttpClient::Get', 'WebRequest::Create'),
           ('Process::Start', 'Assembly::Load', 'Activator::CreateInstance')]),
    Combo('decrypt_load', 'Decrypt and Load In Memory',
          'A payload is decoded or decrypted and then loaded as .NET code without ever '
          'being written to disk. This is the standard .NET packer shape.',
          'warning', 'behaviour',
          [('FromBase64String', 'CryptoStream', 'RijndaelManaged', 'AesManaged', 'TripleDES'),
           ('Assembly::Load', 'AppDomain::Load')]),
    Combo('reflective_loader', 'Reflective Loader Chain',
          'An assembly is loaded and then entered by name through reflection. The real '
          'entry point is chosen at run time, so it never appears in the call graph.',
          'warning', 'behaviour',
          [('Assembly::Load', 'AppDomain::Load'),
           ('MethodBase::Invoke', 'MethodInfo::Invoke', 'Activator::CreateInstance',
            'Type::GetMethod')]),
    Combo('native_exec', 'Managed-to-Native Execution',
          'Unmanaged memory is allocated and a function pointer is taken from it. This '
          'is how managed code hands control to shellcode.',
          'warning', 'behaviour',
          [('Marshal::AllocHGlobal', 'VirtualAlloc', 'Marshal::AllocCoTaskMem'),
           ('Marshal::GetDelegateForFunctionPointer', 'Marshal::Copy', 'CreateThread')]),
    Combo('anti_debug_module', 'Anti-Debug Kill Switch',
          'Looks for a profiler or debugger and kills the process if it finds one. This is the '
          'shape of the anti-debug protection that obfuscators such as ConfuserEx inject.',
          'warning', 'behaviour',
          [('_enable_profiling', 'Debugger::IsAttached', 'Debugger::IsLogging',
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent'),
           ('Environment::FailFast', 'Environment::Exit', 'Process::Kill')]),
    Combo('persist_after_drop', 'Drop and Persist',
          'A file is written and then registered to run at startup.',
          'warning', 'behaviour',
          [('File::WriteAllBytes', 'File::Copy', 'File::WriteAllText'),
           ('Registry', 'currentversion\\run', 'TaskService')]),
]


class CilContext:
    """What the rules query: resolved calls, opcodes and declarations."""

    def __init__(self, annotations, lines):
        self.calls = []
        self.opcodes = []
        self.declarations = []
        self.strings = []
        for a in annotations:
            if a.get('call'):
                self.calls.append((a['index'], a['call']['target']))
            if a['kind'] == 'instruction' and a.get('mnemonic'):
                self.opcodes.append((a['index'], a['mnemonic']))
                for op in a.get('operands', []):
                    if op['kind'] == 'string':
                        text = op['text'].strip('"')
                        self.strings.append((a['index'], text))
                        # Literals are matched too: "cmd.exe" is evidence by itself.
                        self.calls.append((a['index'], text))
            if a['kind'] == 'directive':
                self.declarations.append((a['index'], a['raw']))

    @classmethod
    def from_parts(cls, calls, opcodes, declarations):
        """Build a context directly, for scanning decoded bytecode."""
        ctx = cls([], [])
        ctx.calls = list(calls)
        ctx.opcodes = list(opcodes)
        ctx.declarations = list(declarations)
        return ctx


def detect(annotations, lines) -> List[dict]:
    return run_rules(CilContext(annotations, lines))


def run_rules(ctx) -> List[dict]:
    results = []
    for rule in list(RULES) + list(COMBOS):
        try:
            hits, evidence = rule.match(ctx)
        except Exception:
            hits, evidence = [], []
        if hits:
            results.append({
                'id': rule.id, 'name': rule.name, 'description': rule.description,
                'severity': rule.severity, 'category': rule.category,
                'lines': hits[:40], 'count': len(hits),
                'evidence': evidence[:8],
            })
    order = {'warning': 0, 'notable': 1, 'info': 2}
    results.sort(key=lambda r: (order.get(r['severity'], 3), r['name']))
    return results
