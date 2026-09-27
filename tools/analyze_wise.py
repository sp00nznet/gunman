"""Analyze the Wise installer overlay format."""
import struct
import os

path = 'D:/recomp/pc/gunman/game_extract/REWOLF/INSTALL.EXE'

with open(path, 'rb') as f:
    # Overlay starts at 0x3A00
    f.seek(0x3A00)
    overlay = f.read(64)
    print(f'Overlay header (64 bytes): {overlay.hex()}')

    # Read header values
    f.seek(0x3A00)
    vals = struct.unpack('<8I', f.read(32))
    for i, v in enumerate(vals):
        print(f'  Header[{i}]: {v} (0x{v:X})')

    # Scan the first 16KB of overlay for readable filenames
    f.seek(0x3A00)
    chunk = f.read(16384)
    print('\nSearching for filename strings in overlay...')
    i = 0
    strings_found = []
    while i < len(chunk):
        if 0x20 <= chunk[i] < 0x7f:
            end = i
            while end < len(chunk) and 0x20 <= chunk[end] < 0x7f:
                end += 1
            s = chunk[i:end].decode('ascii')
            bslash = chr(92)  # backslash
            if len(s) > 3 and ('.' in s or bslash in s or '/' in s):
                strings_found.append((i + 0x3A00, s))
            i = end
        else:
            i += 1

    for offset, s in strings_found[:30]:
        print(f'  0x{offset:X}: {s}')

    # Also try: look for "deflate" compressed data (zlib magic 0x78)
    f.seek(0x3A00)
    data = f.read(1024)
    for i in range(len(data) - 1):
        if data[i] == 0x78 and data[i+1] in (0x01, 0x5E, 0x9C, 0xDA):
            print(f'\nPossible zlib stream at overlay+0x{i:X} (abs 0x{0x3A00+i:X})')

    # Try the approach used by E_WISE: Wise installer has a specific structure
    # The overlay data typically starts with a 4-byte size of the "script" data
    # followed by the script (which is PKware DCL imploded)
    f.seek(0x3A00)
    script_size = struct.unpack('<I', f.read(4))[0]
    print(f'\nFirst dword (possible script size): {script_size} (0x{script_size:X})')

    # In some Wise formats, the structure is:
    # [4 bytes: compressed script size] [compressed script] [file data...]
    # Let's check what's at offset 0x3A00 + 4 + script_size
    check_offset = 0x3A00 + 4 + script_size
    f.seek(check_offset)
    after_script = f.read(64)
    print(f'Data at 0x{check_offset:X} (after script_size block):')
    print(f'  {after_script[:32].hex()}')
    print(f'  {after_script[32:64].hex()}')
