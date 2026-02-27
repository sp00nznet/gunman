"""Catalog all DLLs and EXEs in the Gunman Chronicles installation."""
import struct
import os
import hashlib
import datetime

def analyze_pe(filepath):
    """Analyze a PE file and return key metadata."""
    info = {'path': filepath, 'size': os.path.getsize(filepath)}

    with open(filepath, 'rb') as f:
        data = f.read()

    # MD5/SHA1
    info['md5'] = hashlib.md5(data).hexdigest()
    info['sha1'] = hashlib.sha1(data).hexdigest()

    if data[:2] != b'MZ':
        info['error'] = 'Not a PE file'
        return info

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        info['error'] = 'Invalid PE signature'
        return info

    # COFF header
    machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    timestamp = struct.unpack_from('<I', data, pe_offset + 8)[0]
    characteristics = struct.unpack_from('<H', data, pe_offset + 22)[0]

    info['machine'] = {0x14c: 'x86 (i386)', 0x8664: 'x86_64 (AMD64)'}.get(machine, f'0x{machine:X}')
    info['num_sections'] = num_sections
    info['timestamp'] = timestamp
    try:
        info['timestamp_str'] = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        info['timestamp_str'] = 'invalid'
    info['is_dll'] = bool(characteristics & 0x2000)
    info['is_exe'] = not info['is_dll']

    # Optional header
    opt_magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
    info['pe_type'] = {0x10b: 'PE32', 0x20b: 'PE32+'}.get(opt_magic, f'0x{opt_magic:X}')

    opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]

    # Linker version
    linker_major = data[pe_offset + 26]
    linker_minor = data[pe_offset + 27]
    info['linker_version'] = f'{linker_major}.{linker_minor}'

    # Subsystem
    if opt_magic == 0x10b:  # PE32
        subsystem = struct.unpack_from('<H', data, pe_offset + 92)[0]
    else:
        subsystem = struct.unpack_from('<H', data, pe_offset + 108)[0]
    info['subsystem'] = {1: 'Native', 2: 'Windows GUI', 3: 'Windows Console'}.get(subsystem, f'{subsystem}')

    # Sections
    section_offset = pe_offset + 24 + opt_header_size
    sections = []
    max_end = 0
    for i in range(num_sections):
        off = section_offset + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, off + 8)[0]
        vaddr = struct.unpack_from('<I', data, off + 12)[0]
        raw_size = struct.unpack_from('<I', data, off + 16)[0]
        raw_offset = struct.unpack_from('<I', data, off + 20)[0]
        chars = struct.unpack_from('<I', data, off + 36)[0]

        flags = []
        if chars & 0x20: flags.append('CODE')
        if chars & 0x40: flags.append('IDATA')
        if chars & 0x80: flags.append('UDATA')
        if chars & 0x20000000: flags.append('EXEC')
        if chars & 0x40000000: flags.append('READ')
        if chars & 0x80000000: flags.append('WRITE')

        end = raw_offset + raw_size
        if end > max_end:
            max_end = end
        sections.append({
            'name': name, 'vsize': vsize, 'vaddr': vaddr,
            'raw_size': raw_size, 'raw_offset': raw_offset,
            'flags': '|'.join(flags)
        })
    info['sections'] = sections

    # Check for UPX packing
    section_names = [s['name'] for s in sections]
    info['packed_upx'] = 'UPX0' in section_names or 'UPX1' in section_names

    # Overlay
    overlay_size = len(data) - max_end
    info['overlay_size'] = overlay_size

    # Import table - just list DLL names
    if opt_magic == 0x10b:
        import_rva = struct.unpack_from('<I', data, pe_offset + 24 + 104)[0]
        import_size = struct.unpack_from('<I', data, pe_offset + 24 + 108)[0]
    else:
        import_rva = struct.unpack_from('<I', data, pe_offset + 24 + 120)[0]
        import_size = struct.unpack_from('<I', data, pe_offset + 24 + 124)[0]

    imports = []
    if import_rva > 0 and import_size > 0:
        # Convert RVA to file offset
        for s in sections:
            if s['vaddr'] <= import_rva < s['vaddr'] + s['vsize']:
                import_file_off = import_rva - s['vaddr'] + s['raw_offset']
                # Read import descriptors
                pos = import_file_off
                while pos + 20 <= len(data):
                    name_rva = struct.unpack_from('<I', data, pos + 12)[0]
                    if name_rva == 0:
                        break
                    # Convert name RVA to file offset
                    for s2 in sections:
                        if s2['vaddr'] <= name_rva < s2['vaddr'] + s2['vsize']:
                            name_off = name_rva - s2['vaddr'] + s2['raw_offset']
                            end = data.index(b'\x00', name_off)
                            dll_name = data[name_off:end].decode('ascii', errors='replace')
                            imports.append(dll_name)
                            break
                    pos += 20
                break
    info['imports'] = imports

    # Export table - count and list first few
    if opt_magic == 0x10b:
        export_rva = struct.unpack_from('<I', data, pe_offset + 24 + 96)[0]
        export_size = struct.unpack_from('<I', data, pe_offset + 24 + 100)[0]
    else:
        export_rva = struct.unpack_from('<I', data, pe_offset + 24 + 112)[0]
        export_size = struct.unpack_from('<I', data, pe_offset + 24 + 116)[0]

    exports = []
    if export_rva > 0 and export_size > 0:
        for s in sections:
            if s['vaddr'] <= export_rva < s['vaddr'] + s['vsize']:
                exp_off = export_rva - s['vaddr'] + s['raw_offset']
                num_names = struct.unpack_from('<I', data, exp_off + 24)[0]
                names_rva = struct.unpack_from('<I', data, exp_off + 32)[0]

                for s2 in sections:
                    if s2['vaddr'] <= names_rva < s2['vaddr'] + s2['vsize']:
                        names_off = names_rva - s2['vaddr'] + s2['raw_offset']
                        for j in range(min(num_names, 50)):
                            name_rva2 = struct.unpack_from('<I', data, names_off + j * 4)[0]
                            for s3 in sections:
                                if s3['vaddr'] <= name_rva2 < s3['vaddr'] + s3['vsize']:
                                    n_off = name_rva2 - s3['vaddr'] + s3['raw_offset']
                                    end = data.index(b'\x00', n_off)
                                    exports.append(data[n_off:end].decode('ascii', errors='replace'))
                                    break
                        break
                break
    info['exports'] = exports
    info['num_exports'] = len(exports)

    return info


def main():
    base = 'C:/sierra/gunman'

    # Find all DLLs and EXEs
    targets = []
    for root, dirs, files in os.walk(base):
        for f in files:
            ext = f.lower().split('.')[-1] if '.' in f else ''
            if ext in ('dll', 'exe'):
                targets.append(os.path.join(root, f))

    targets.sort()

    print("=" * 80)
    print("GUNMAN CHRONICLES - BINARY CATALOG")
    print("=" * 80)

    # Categorize
    categories = {
        'ENGINE': [],
        'MOD_CLIENT': [],
        'MOD_SERVER': [],
        'SUPPORT': [],
        'INSTALLER': [],
    }

    for t in targets:
        rel = os.path.relpath(t, base).replace('\\', '/')
        info = analyze_pe(t)
        info['relpath'] = rel

        if 'cl_dlls' in rel:
            categories['MOD_CLIENT'].append(info)
        elif 'dlls/' in rel and 'cl_dlls' not in rel:
            categories['MOD_SERVER'].append(info)
        elif rel in ('hw.dll', 'sw.dll', 'gunman.exe', 'hlds.exe'):
            categories['ENGINE'].append(info)
        elif rel in ('UNWISE.EXE', 'upd.exe'):
            categories['INSTALLER'].append(info)
        else:
            categories['SUPPORT'].append(info)

    for cat_name, cat_files in categories.items():
        if not cat_files:
            continue
        print(f"\n{'=' * 80}")
        print(f"  {cat_name}")
        print(f"{'=' * 80}")
        for info in cat_files:
            print(f"\n  [{info['relpath']}]")
            print(f"  Size: {info['size']:,} bytes")
            print(f"  MD5:  {info['md5']}")
            print(f"  SHA1: {info['sha1']}")
            if 'error' in info:
                print(f"  Error: {info['error']}")
                continue
            print(f"  Type: {info['pe_type']} {'DLL' if info['is_dll'] else 'EXE'} ({info['machine']})")
            print(f"  Linker: {info['linker_version']}")
            print(f"  Subsystem: {info['subsystem']}")
            print(f"  Timestamp: {info['timestamp_str']}")
            print(f"  Packed (UPX): {info['packed_upx']}")
            if info['overlay_size'] > 0:
                print(f"  Overlay: {info['overlay_size']:,} bytes")
            print(f"  Sections ({info['num_sections']}):")
            for s in info['sections']:
                print(f"    {s['name']:8s}  VA=0x{s['vaddr']:08X}  Raw=0x{s['raw_offset']:08X}  "
                      f"Size=0x{s['raw_size']:X}  [{s['flags']}]")
            if info['imports']:
                print(f"  Imports ({len(info['imports'])} DLLs):")
                for imp in info['imports']:
                    print(f"    - {imp}")
            if info['exports']:
                print(f"  Exports ({info['num_exports']}):")
                for exp in info['exports'][:20]:
                    print(f"    - {exp}")
                if info['num_exports'] > 20:
                    print(f"    ... and {info['num_exports'] - 20} more")


if __name__ == '__main__':
    main()
