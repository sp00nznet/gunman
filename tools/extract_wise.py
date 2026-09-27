"""
Extract files from a Wise installer.

Wise installers store data in the PE overlay. The format is:
- Overlay header (variable)
- Compressed script (PKware DCL implode / deflate)
- File data blobs

The script contains file entries with paths and offsets.
We use the inflated script approach with zlib/deflate fallback.
"""
import struct
import zlib
import os
import sys

def find_overlay(data):
    """Find the PE overlay (data after last section)."""
    if data[:2] != b'MZ':
        raise ValueError("Not a PE file")
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
    section_offset = pe_offset + 24 + opt_header_size

    max_end = 0
    for i in range(num_sections):
        off = section_offset + i * 40
        raw_size = struct.unpack_from('<I', data, off + 16)[0]
        raw_offset = struct.unpack_from('<I', data, off + 20)[0]
        end = raw_offset + raw_size
        if end > max_end:
            max_end = end

    return max_end


def try_inflate(data, offset, max_size=50*1024*1024):
    """Try various decompression methods at the given offset."""
    # Try raw deflate
    for wbits in [-15, -14, -13, -12, -11, -10, -9, -8, 15, 31, 47]:
        try:
            dec = zlib.decompressobj(wbits)
            result = dec.decompress(data[offset:offset + max_size])
            if len(result) > 100:
                return result
        except Exception:
            pass
    return None


def extract_wise_script(data, overlay_start):
    """Try to extract and decompress the Wise installer script."""
    # Read the first few dwords from the overlay
    pos = overlay_start
    vals = struct.unpack_from('<8I', data, pos)
    print(f"Overlay header values: {[f'0x{v:X}' for v in vals]}")

    # Strategy 1: First dword might be uncompressed script size
    # Compressed data starts at overlay + some offset
    # Try decompressing from various offsets after the header
    for test_offset in [4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48]:
        abs_offset = overlay_start + test_offset
        result = try_inflate(data, abs_offset)
        if result:
            print(f"Decompressed script from overlay+{test_offset}: {len(result)} bytes")
            return result

    # Strategy 2: Search for zlib headers in first 1KB of overlay
    for i in range(min(1024, len(data) - overlay_start - 1)):
        abs_i = overlay_start + i
        b0 = data[abs_i]
        b1 = data[abs_i + 1] if abs_i + 1 < len(data) else 0
        # zlib header: first byte 0x78, second can be 01, 5E, 9C, DA
        if b0 == 0x78 and b1 in (0x01, 0x5E, 0x9C, 0xDA):
            result = try_inflate(data, abs_i)
            if result:
                print(f"Found zlib stream at overlay+{i}: {len(result)} bytes")
                return result

    return None


def parse_script_for_filenames(script_data):
    """Parse the decompressed Wise script for file paths."""
    filenames = []
    i = 0
    while i < len(script_data):
        # Look for path-like strings
        if script_data[i:i+2] in [b'C:', b'c:', b'%S', b'%s'] or \
           (0x20 < script_data[i] < 0x7f and script_data[i:i+1] in [b'\\', b'/']):
            end = i
            while end < len(script_data) and script_data[end] != 0:
                end += 1
            try:
                s = script_data[i:end].decode('ascii')
                if len(s) > 2:
                    filenames.append((i, s))
            except Exception:
                pass
            i = end + 1
        else:
            i += 1
    return filenames


def brute_force_extract(data, overlay_start, out_dir):
    """
    Try brute-force approach: scan overlay for recognizable file signatures
    and extract them.
    """
    print("\nScanning overlay for known file signatures...")
    sigs = {
        b'MZ': 'exe_or_dll',
        b'MSCF': 'cab',
        b'PK\x03\x04': 'zip',
        b'Rar!': 'rar',
        b'RIFF': 'riff',
    }

    found = []
    pos = overlay_start
    while pos < len(data) - 4:
        for sig, ftype in sigs.items():
            if data[pos:pos+len(sig)] == sig:
                found.append((pos, ftype))
                print(f"  Found {ftype} signature at offset 0x{pos:X}")
        pos += 512  # scan every 512 bytes for speed

    return found


def main():
    installer_path = sys.argv[1] if len(sys.argv) > 1 else \
        'D:/recomp/pc/gunman/game_extract/REWOLF/INSTALL.EXE'
    out_dir = sys.argv[2] if len(sys.argv) > 2 else \
        'D:/recomp/pc/gunman/game_installed'

    print(f"Reading {installer_path}...")
    with open(installer_path, 'rb') as f:
        data = f.read()
    print(f"File size: {len(data):,} bytes")

    overlay_start = find_overlay(data)
    overlay_size = len(data) - overlay_start
    print(f"PE overlay at 0x{overlay_start:X}, size: {overlay_size:,} bytes")

    # Try to extract the script
    print("\nAttempting to decompress installer script...")
    script = extract_wise_script(data, overlay_start)

    if script:
        # Save the raw script for analysis
        script_path = os.path.join(out_dir, '_wise_script.bin')
        os.makedirs(out_dir, exist_ok=True)
        with open(script_path, 'wb') as f:
            f.write(script)
        print(f"Saved script to {script_path}")

        # Look for filenames in the script
        filenames = parse_script_for_filenames(script)
        if filenames:
            print(f"\nFound {len(filenames)} path-like strings in script:")
            for offset, fn in filenames[:50]:
                print(f"  0x{offset:X}: {fn}")
    else:
        print("Could not decompress script with standard methods.")
        print("Wise installer likely uses PKware DCL Implode compression.")

    # Try brute force signature scan
    found = brute_force_extract(data, overlay_start, out_dir)
    print(f"\nTotal signatures found in overlay: {len(found)}")


if __name__ == '__main__':
    main()
