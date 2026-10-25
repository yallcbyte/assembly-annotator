# Assembly Annotator

Paste assembly, read plain English.

Assembly Annotator explains a listing line by line, names the patterns it finds,
and resolves the branches between them. It is aimed at reverse engineers, CTF
players, students and anyone who has stared at a disassembly wondering what it
actually *does*.

![The annotated view](docs/screenshot-terminal.png)

---

## What it does

**Every line gets a sentence, not a dictionary entry.** The explanation is built
from the operands, so `mov ecx, 5` reads *"Set ECX (counter) to 5"* rather than
"copy data from source to destination". Labels, directives and comments are
classified as what they are instead of being reported as unknown instructions.

**Idioms are named.** `xor eax, eax` is *"Zero out EAX"*. `sub esp, 0x20` is
*"Reserve 32 bytes of local stack space"*. `shl eax, 3` is *"Multiply EAX by 8"*.
`test eax, eax` is *"Check whether EAX is zero"*.

**Constants are followed forward.** A light register model propagates immediates
through the listing, so by the time it reaches `int 0x80` it knows EAX held 4 and
reports *"Invoke the write() system call"*. Packed immediates are decoded too —
`push 0x6e69622f` is flagged as the ASCII text `/bin` being assembled on the stack.

**Patterns come with reasons.** Each detection carries a plain-English
description, a severity, and the exact lines that triggered it. Click a pattern
to highlight those lines in both panes.

![Pattern detection](docs/screenshot-patterns.png)

**Branches resolve.** Jump targets are matched to the lines that define them, so
every branch shows where it goes, backward jumps are marked as loops, and code
nothing reaches is flagged as unreachable.

**Three views of the same listing.** *Lines* is the annotated listing. *Graph*
draws the control-flow graph as basic blocks, with branch-taken, fall-through,
unconditional and back edges each drawn differently. *Stack* reconstructs the
frame: which slot is which argument, which are locals, where the saved frame
pointer and return address sit, and which lines read or write each one.

![Control-flow graph](docs/screenshot-graph.png)

**Bytes in, not just text.** Switch the source pane to *Bytes* and paste raw
machine code - plain hex, `\x` escapes, a C array, `xxd` or `hexdump -C` output
all parse. Or drop in a binary: ELF files have their `.text` section extracted
automatically, with the real virtual address as the base. Capstone does the
disassembly, and the result is annotated like any other listing.

![Stack frame](docs/screenshot-frame.png)

**.NET, read at the level of calls.** Paste IL from ILSpy, dnSpy or ildasm and
the annotator switches to a separate CIL engine. CIL is a stack machine, so it
models the evaluation stack: a literal pushed with `ldstr`, stored to a local
and loaded back is named again at the call that finally consumes it.

```
ldstr    "http://198.51.100.7/update.txt"
callvirt instance string WebClient::DownloadString(string)
  -> Call WebClient.DownloadString on a WebClient, passing "http://198.51.100.7/update.txt"
```

Because .NET metadata names every callee, detection works on resolved APIs,
not instruction shapes. Each finding lists the calls that triggered it, and the
strongest ones are composites, such as Base64 decode followed by
`Assembly.Load` followed by `MethodBase.Invoke`, which together form a
reflective loader. Properties read as properties (`Read Environment.UserName`,
not `get_UserName`), every line shows its stack depth, and the Stack view lists
the typed local slots with the lines that read and write each one.

![.NET analysis](docs/screenshot-dotnet.png)

**Open a .NET assembly directly.** Drop a `.dll` or `.exe` on the Bytes tab and
it opens in a method browser: assembly identity and references, every rule that
fired anywhere in the file with how many methods it fired in, and the P/Invoke
table of native functions it can reach. Click a finding to list only the methods
that triggered it; click a method to decode its IL, with every metadata token
resolved to a name, and annotate it like any other listing. The file is parsed
in memory and never executed. A 450 KB, 3,900-method assembly loads and scans in
about two seconds.

![.NET method](docs/screenshot-dotnet-method.png)

---

## Input it understands

| Input | Notes |
| --- | --- |
| x86 / x86-64 | 210+ mnemonics including the full `jcc` / `setcc` / `cmovcc` families |
| ARM / AArch64 | prologue pairs, `svc` system calls, conditional branches |
| MIPS | core integer and branch instructions |
| Intel syntax | `mov eax, 1` |
| AT&T syntax | `movl $1, %eax` — operands are flipped so explanations read the same way |
| objdump / gdb | addresses, opcode bytes and `<function>:` headers are parsed and dimmed |
| Raw bytes | hex, `\x` escapes, C arrays, `xxd` and `hexdump -C` dumps |
| ELF binaries | `.text` is located and disassembled at its real load address |
| .NET IL | ildasm, ILSpy and dnSpy output, with `.method`, `.locals` and `.maxstack` context |
| .NET assemblies | `.dll` / `.exe` opened directly: method browser, IL decoding, whole-file scan |
| NASM / GAS | sections, `global`, data definitions, `;` `#` and `//` comments |

Architecture and syntax are auto-detected; both can be forced from the toolbar.

---

## Interface

- **Split view** — editable source on the left with line numbers and syntax
  highlighting, annotations on the right, draggable divider.
- **Three detail levels** — *brief* for a quick pass, *normal*, or *verbose*,
  which adds tracked register values and flag effects.
- **Filter** — type `jmp`, `stack` or `syscall` to narrow the annotations.
- **Three views** — annotated lines, control-flow graph, stack frame.
- **Four themes** — terminal, midnight, amber and light.
- **Export** — Markdown report, aligned plain text, full JSON (including the
  control-flow graph), or copy to the clipboard.
- **Keyboard** — <kbd>Ctrl</kbd>+<kbd>Enter</kbd> analyze,
  <kbd>Ctrl</kbd>+<kbd>K</kbd> filter, <kbd>Ctrl</kbd>+<kbd>/</kbd> expand all.
- **Eight worked examples** in the Examples menu, from a counted loop to
  `execve` shellcode to raw objdump output.

![Light theme](docs/screenshot-light.png)

The front end is plain HTML, CSS and JavaScript — no framework, no CDN, no build
step. Nothing you paste leaves your machine beyond the local Flask process, and
nothing is stored server-side.

---

## Running it

```bash
git clone git@github.com:yallcbyte/assembly-annotator.git
cd assembly-annotator
./run.sh
```

Then open <http://127.0.0.1:5000>. `run.sh` creates a virtualenv on first run.

Manually, if you prefer:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py          # PORT=8080 to change the port
```

Requires Python 3.9+ and Flask. `capstone` enables the *Bytes* input mode and
`dnfile` enables opening .NET assemblies; without either, the rest of the app
works unchanged.

---

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

298 tests cover parsing, explanation, pattern detection, control flow and the
HTTP API, including a check that every bundled example is fully recognised.

---

## HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/annotate` | Analyze a listing. Body: `{code, arch?, syntax?, verbosity?}` |
| `POST` | `/api/disassemble` | Bytes to assembly. JSON `{hex, arch?, bits?, base?}`, or a multipart `file` |
| `POST` | `/api/dotnet/load` | Open a .NET assembly (multipart `file`): overview, findings, methods |
| `GET` | `/api/dotnet/<sha256>/method/<id>` | One method as IL, ready for `/api/annotate` |
| `POST` | `/api/export/{md,txt,json}` | Same analysis as a downloadable report |
| `GET` | `/api/examples` · `/api/examples/<id>` | Bundled examples |
| `GET` | `/api/instruction/<mnemonic>` | Instruction reference entry |
| `GET` | `/api/register/<name>` | Register role, width and parent |
| `GET` | `/api/health` | Status and database size |

```bash
curl -s localhost:5000/api/annotate \
  -H 'Content-Type: application/json' \
  -d '{"code":"xor eax, eax\nmov al, 11\nint 0x80"}' | jq '.stats.syscalls'
# ["execve"]
```

---

## Code layout

```
annotator/
  parser.py      line classification: labels, directives, comments, objdump, AT&T
  isa.py         instruction database, categories, condition codes
  registers.py   register roles, widths and 64-bit parents
  syscalls.py    Linux x86 / x86-64 / AArch64 syscall tables
  explain.py     operand-aware sentences, idiom recognition, register tracking
  patterns.py    pattern engine with severities and line evidence
  cfg.py         branch resolution, loop headers, unreachable code, basic blocks
  frames.py      stack frame layout: arguments, locals, saved pointer, return address
  disasm.py      hex and ELF parsing, Capstone disassembly
  cil/           .NET: opcode table and signatures, IL parser,
                 evaluation-stack explainer, API rules, pipeline,
                 IL byte decoder, signature blobs, assembly loader
  analyzer.py    orchestration and summary statistics
  examples.py    bundled sample listings
app.py           Flask routes and report rendering
static/          one stylesheet, one script
templates/       one page
tests/           298 tests
```

### Adding an instruction

```python
# annotator/isa.py
'adcx': _i('Add with carry (unsigned)', 'arith',
           'Add the source plus the carry flag, unsigned',
           'Add {src} plus the carry flag to {dst}', 'CF',
           'Used in wide-integer arithmetic alongside ADOX.'),
```

`{dst}`, `{src}` and `{op0}`…`{op3}` are filled from the parsed operands.

### Adding a pattern

```python
# annotator/patterns.py
Pattern('my_check', 'Human-readable Name',
        'What the reader should take away from this.',
        'notable', 'control', any_of=['cmp', 'test']),
```

Patterns match on an ordered `sequence`, `all_of`, `any_of`, a `regex`, or a
`custom` callable that receives the match context and returns line numbers.

---

## Credit

Forked from [zoecyber001/assembly-annotator](https://github.com/zoecyber001/assembly-annotator),
originally made for the Cybersecurity Committee by ZoeCyber.

## Licence

MIT — see [LICENSE](LICENSE).
