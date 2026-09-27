#!/usr/bin/env python3
"""Disassemble N instructions at a VA of a rebased module: tools/disat.py 0x0A028BEE [n]"""
import sys, os, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
va = int(sys.argv[1], 16); n = int(sys.argv[2]) if len(sys.argv) > 2 else 40
for f in os.listdir(os.path.join(ROOT, 'work', 'rebased')):
    pe = pefile.PE(os.path.join(ROOT, 'work', 'rebased', f), fast_load=True)
    b = pe.OPTIONAL_HEADER.ImageBase
    if b <= va < b + pe.OPTIONAL_HEADER.SizeOfImage:
        data = pe.get_memory_mapped_image()[va - b:va - b + n * 16]
        for i, ins in enumerate(Cs(CS_ARCH_X86, CS_MODE_32).disasm(data, va)):
            if i >= n: break
            print('%08X  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
