# Ghidra headless script: Export all function info to a file
# Run with: analyzeHeadless ... -postScript ghidra_export_functions.py
#
# This exports:
# - Function name, address, size
# - Demangled name (for C++ symbols)
# - Whether it looks like a thunk/wrapper
# - Import/export status

import os

# Output path - next to the analyzed binary
output_dir = "D:/recomp/pc/gunman/disasm"
program_name = currentProgram.getName().replace(".dll", "").replace(".exe", "")
output_path = os.path.join(output_dir, program_name + "_functions.txt")

listing = currentProgram.getListing()
func_manager = currentProgram.getFunctionManager()
symbol_table = currentProgram.getSymbolTable()

functions = []
func_iter = func_manager.getFunctions(True)
while func_iter.hasNext():
    func = func_iter.next()
    entry = func.getEntryPoint()
    body = func.getBody()
    size = body.getNumAddresses() if body else 0
    name = func.getName()

    # Check if external/thunk
    is_thunk = func.isThunk()
    is_external = func.isExternal()

    # Try to get demangled name
    demangled = None
    sym = symbol_table.getPrimarySymbol(entry)
    if sym:
        source = sym.getSource()

    # Get calling convention
    cc = func.getCallingConventionName()

    # Count references to this function
    ref_manager = currentProgram.getReferenceManager()
    refs_to = ref_manager.getReferencesTo(entry)
    ref_count = 0
    for r in refs_to:
        ref_count += 1

    functions.append({
        'addr': entry.toString(),
        'name': name,
        'size': size,
        'is_thunk': is_thunk,
        'is_external': is_external,
        'calling_conv': cc if cc else 'unknown',
        'ref_count': ref_count,
    })

# Sort by address
functions.sort(key=lambda f: f['addr'])

# Write output
with open(output_path, 'w') as f:
    f.write("# Ghidra Function Export: %s\n" % currentProgram.getName())
    f.write("# Total functions: %d\n" % len(functions))
    f.write("# Format: address | size | refs | calling_conv | flags | name\n")
    f.write("#" + "=" * 100 + "\n")

    thunk_count = 0
    external_count = 0
    named_count = 0

    for func in functions:
        flags = []
        if func['is_thunk']:
            flags.append('THUNK')
            thunk_count += 1
        if func['is_external']:
            flags.append('EXT')
            external_count += 1
        if not func['name'].startswith('FUN_'):
            named_count += 1

        flag_str = ','.join(flags) if flags else '-'

        f.write("%s | %6d | %4d | %-12s | %-10s | %s\n" % (
            func['addr'],
            func['size'],
            func['ref_count'],
            func['calling_conv'],
            flag_str,
            func['name']
        ))

    f.write("\n# Summary:\n")
    f.write("#   Total functions: %d\n" % len(functions))
    f.write("#   Named (non-FUN_): %d\n" % named_count)
    f.write("#   Auto-named (FUN_): %d\n" % (len(functions) - named_count))
    f.write("#   Thunks: %d\n" % thunk_count)
    f.write("#   External: %d\n" % external_count)

print("Exported %d functions to %s" % (len(functions), output_path))
