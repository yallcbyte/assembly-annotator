import struct
import subprocess
import sys

import pytest

from annotator import analyse
from annotator.disasm import (
    AVAILABLE, Binary, DisasmError, disassemble, load, looks_like_elf, parse_hex,
)

# execve("/bin/sh") -- small, well known, and every format below encodes it.
SHELLCODE = bytes.fromhex('31c050682f2f7368682f62696e89e3b00bcd80')

needs_capstone = pytest.mark.skipif(not AVAILABLE, reason='capstone not installed')


@pytest.mark.parametrize('text', [
    '31c050682f2f7368682f62696e89e3b00bcd80',
    '31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 b0 0b cd 80',
    '31C0 5068 2F2F 7368 682F 6269 6E89 E3B0 0BCD 80',
    r'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80',
    r'char sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";',
    '{0x31,0xc0,0x50,0x68,0x2f,0x2f,0x73,0x68,0x68,0x2f,0x62,0x69,0x6e,0x89,0xe3,0xb0,0x0b,0xcd,0x80}',
    # xxd
    '00000000: 31c0 5068 2f2f 7368 682f 6269 6e89 e3b0  1.Ph//shh/bin...\n'
    '00000010: 0bcd 80                                  ...',
    # hexdump -C, including its trailing length line
    '00000000  31 c0 50 68 2f 2f 73 68  68 2f 62 69 6e 89 e3 b0  |1.Ph//shh/bin...|\n'
    '00000010  0b cd 80                                          |...|\n'
    '00000013',
])
def test_hex_formats_all_decode_to_the_same_bytes(text):
    assert parse_hex(text) == SHELLCODE


@pytest.mark.parametrize('bad,message', [
    ('', 'No bytes'),
    ('   ', 'No bytes'),
    ('hello world', 'not pure hex'),
    ('31c0 5', 'odd number'),
    ('zz ff', 'not pure hex'),
])
def test_hex_errors_explain_themselves(bad, message):
    with pytest.raises(DisasmError, match=message):
        parse_hex(bad)


def test_oversized_hex_is_rejected():
    with pytest.raises(DisasmError, match='over the'):
        parse_hex('41' * 300_000)


@needs_capstone
def test_disassembly_round_trips_through_the_analyser():
    out = disassemble(SHELLCODE, 'x86', 32)
    assert out['instructions'] == 7
    assert out['undecoded_bytes'] == 0
    result = analyse(out['text'])
    # The disassembled text must be fully understood by the existing pipeline.
    assert result['stats']['unknown_mnemonics'] == []
    assert 'execve' in result['stats']['syscalls']


@needs_capstone
def test_base_address_is_honoured():
    out = disassemble(SHELLCODE, 'x86', 32, base=0x400000)
    assert out['text'].startswith('00400000:')


@needs_capstone
def test_wrong_bit_width_still_produces_something_rather_than_crashing():
    assert disassemble(SHELLCODE, 'x86', 64)['instructions'] > 0


@needs_capstone
def test_unsupported_architecture_is_reported():
    with pytest.raises(DisasmError, match='No disassembler'):
        disassemble(SHELLCODE, 'sparc', 32)


@needs_capstone
def test_empty_input_is_reported():
    with pytest.raises(DisasmError, match='No bytes'):
        disassemble(b'', 'x86', 32)


@needs_capstone
def test_non_code_bytes_are_skipped_not_fatal():
    out = disassemble(b'\xff\xff\xff\xff' * 4, 'x86', 32)
    assert out['instructions'] > 0


# ---- containers --------------------------------------------------------

def test_raw_bytes_pass_through_load():
    b = load(SHELLCODE)
    assert b.source == 'raw' and b.data == SHELLCODE and b.base == 0


def test_pe_is_rejected_with_a_useful_message():
    with pytest.raises(DisasmError, match='PE/EXE'):
        load(b'MZ' + b'\x00' * 64)


def test_looks_like_elf():
    assert looks_like_elf(b'\x7fELF' + b'\x00' * 20)
    assert not looks_like_elf(SHELLCODE)


def test_truncated_elf_does_not_crash():
    with pytest.raises(DisasmError):
        load(b'\x7fELF' + b'\x00' * 8)


@pytest.mark.skipif(sys.platform != 'linux', reason='needs a linux toolchain')
def test_real_elf_text_section_is_extracted(tmp_path):
    src = tmp_path / 'p.c'
    src.write_text('int f(int k){return k==0x1337C0DE;}\nint main(void){return f(1);}\n')
    exe = tmp_path / 'p'
    try:
        subprocess.run(['gcc', '-O0', '-o', str(exe), str(src)],
                       check=True, capture_output=True, timeout=60)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pytest.skip('no working gcc')

    binary = load(exe.read_bytes())
    assert binary.source == 'elf'
    assert binary.arch == 'x86' and binary.bits == 64
    assert binary.base > 0 and len(binary.data) > 0
    assert '.text' in binary.note

    if AVAILABLE:
        out = disassemble(binary.data, binary.arch, binary.bits, binary.base)
        result = analyse(out['text'])
        # A stock compiled binary should be fully covered and raise no alarms.
        assert result['stats']['unknown_mnemonics'] == []
        assert result['stats']['warnings'] == []
