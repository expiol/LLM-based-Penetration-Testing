"""Prompts for cryptography challenges."""

from __future__ import annotations

from killchain_docker.prompts.types import CategoryPrompts, register

register(CategoryPrompts(
    category="crypto",
    objective_hint=(
        "Identify the cipher/algorithm used, look for known-plaintext attacks "
        "(file headers like PNG magic bytes), weak keys, small primes, "
        "or reversible operations. Try running any bundled scripts and check "
        "if output can be decoded. Derive the flag mathematically when possible."
    ),
    planner_system=(
        "You are planning a cryptography CTF challenge. Crypto challenges require "
        "identifying and breaking or exploiting weaknesses in cryptographic "
        "implementations. Common themes: RSA with small primes or shared factors, "
        "block cipher ECB mode, XOR with repeating key, LFSR, custom ciphers, "
        "and mathematical attacks on number theory."
    ),
    planner_focus=(
        "Prioritize: 1) Source code review to identify the algorithm, "
        "2) Parameter extraction (keys, moduli, ciphertexts, IVs), "
        "3) Mathematical analysis of the cryptosystem weaknesses, "
        "4) Writing and executing a decryption/script, "
        "5) Known-plaintext attacks if partial plaintext is available. "
        "6) Dynamic analysis with ltrace/strace if the challenge is a binary."
    ),
    analysis_strategy=(
        "Available tools in container: sagemath (run via 'sage -python script.py' or "
        "'sage -c \"...\"'), pwntools (python3: from pwn import *), gmpy2, z3-solver, "
        "pycryptodome, sympy, angr, ltrace, strace. "
        "For crypto challenges: identify which algorithm is used (RSA, AES, DES, "
        "XOR, custom). Extract all parameters: public keys, moduli, exponents, "
        "ciphertexts, IVs, nonces. Check for weak parameters: small RSA primes "
        "(factorable via factordb), reused nonces, ECB mode, short XOR keys. "
        "Look for known-plaintext opportunities (file headers, flag format prefix). "
        "For binary crypto programs: use ltrace to trace library calls (e.g. "
        "libc random, openssl) and strace for file I/O to understand the algorithm "
        "without full reverse engineering."
    ),
    exploit_strategy=(
        "Apply the appropriate mathematical attack: factor RSA modulus if small, "
        "use Wiener's attack for large e, Hastad's broadcast attack for small e, "
        "XOR ciphertext with known plaintext to recover key, break LFSR with "
        "known output bits. Write a Python script using standard crypto "
        "libraries (pycryptodome, gmpy2, sympy) and execute it. "
        "For constraint-based challenges, use z3-solver to model the system. "
        "For number-theory attacks (discrete log, lattice reduction, Coppersmith), "
        "use SageMath: write a .sage or .py script and run with 'sage -python'. "
        "For challenges with a network service, use pwntools remote() for "
        "protocol interaction (handles PoW, sends/receives data reliably)."
    ),
    flag_recovery_hints=[
        "Factor RSA modulus using factordb or yafu",
        "XOR ciphertext with known flag format prefix to recover key fragment",
        "Check if ECB mode leaks block patterns",
        "Try small exponent attacks for RSA",
        "Use z3-solver for constraint-based solving (custom ciphers, hash preimage)",
        "Use sage for number theory attacks (discrete log, lattice reduction)",
        "Use ltrace on crypto binaries to capture algorithm parameters at runtime",
        "Use pwntools remote() for network protocol interaction with PoW support",
    ],
))
