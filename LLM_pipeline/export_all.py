#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.listing import Listing
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Instruction
from ghidra.program.model.listing import Data


program = currentProgram
listing = program.getListing()
fm = program.getFunctionManager()
symtab = currentProgram.getSymbolTable()

output = {
    "binary": str(program.getName()),
    "arch": str(program.getLanguage().getProcessor()),
    "functions": {}
}

decomp = DecompInterface()
decomp.openProgram(program)
monitor = ConsoleTaskMonitor()

# ----------------------
# Helper Functions
# ----------------------

def get_cfg(func):
    cfg = {"nodes": [], "edges": []}
    bbm = BasicBlockModel(currentProgram)
    blocks = bbm.getCodeBlocksContaining(func.getBody(), monitor)

    block_list = []
    for b in blocks:
        node = {
            "id": hex(b.getFirstStartAddress().getOffset()),
            "start": str(b.getFirstStartAddress())
        }
        cfg["nodes"].append(node)
        block_list.append(b)

    for src_b in block_list:
        dest_iter = src_b.getDestinations(monitor)
        while dest_iter.hasNext():
            ref = dest_iter.next()
            dst_b = ref.getDestinationBlock()
            if dst_b:
                cfg["edges"].append({
                    "from": hex(src_b.getFirstStartAddress().getOffset()),
                    "to": hex(dst_b.getFirstStartAddress().getOffset())
                })
    return cfg

def get_asm(func):
    return [str(instr) for instr in listing.getInstructions(func.getBody(), True)]

def get_decomp(func):
    res = decomp.decompileFunction(func, 30, monitor)
    if res:
        return res.getDecompiledFunction().getC()
    return ""

def get_calls(func):
    calls = []
    for instr in listing.getInstructions(func.getBody(), True):
        if instr.getFlowType().isCall():
            for ref in instr.getReferencesFrom():
                if ref.getReferenceType().isCall():
                    # Resolve to function name if possible
                    called_func = fm.getFunctionAt(ref.getToAddress())
                    if called_func:
                        calls.append(str(called_func.getName()))
                    else:
                        calls.append(str(ref.getToAddress()))
    return calls

def get_imports():
    imports = []
    for s in symtab.getSymbols(True):
        if s.getSymbolType() == SymbolType.FUNCTION and s.isExternal():
            imports.append(s.getName())
    return imports

def get_strings():
    strings = []
    for s in listing.getDefinedData(True):
        if s.getDataType().getName() == "string":
            try:
                strings.append(s.getValue())
            except:
                pass
    return strings

# ----------------------
# Detect main function
# ----------------------
main_func = getFunctionContaining(currentAddress)

if main_func is None:
    print("No main function found in binary.")
else:
    # ----------------------
    # Functions to export: main + direct calls
    # ----------------------
    functions_to_export = [main_func]

    # Build lookup table: name -> function
    all_funcs = list(fm.getFunctions(True))
    name_to_func = {f.getName(): f for f in all_funcs}

    # Add functions called by main
    for call_name in get_calls(main_func):
        if call_name in name_to_func and name_to_func[call_name] not in functions_to_export:
            functions_to_export.append(name_to_func[call_name])

    # ----------------------
    # Export each function
    # ----------------------
    for func in functions_to_export:
        fn_entry = {
            "name": str(func.getName()),
            "address": str(func.getEntryPoint()),
            "signature": func.getSignature().getPrototypeString(),
            "asm": get_asm(func),
            "decomp": get_decomp(func),
            "cfg": get_cfg(func),
            "callgraph": {"calls": get_calls(func)},
            "imports": get_imports(),
            # "strings": get_strings()
        }
        output["functions"][func.getName()] = fn_entry

# ----------------------
# Write JSON
# ----------------------
# Get the user's home directory. This is a cross-platform solution.
home_dir = os.path.expanduser('~')
output_dir = os.path.join(home_dir, "ghidra_output")
# Create the output directory if it doesn't exist
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

outfile = program.getName() + "_analysis.json"
output_path = os.path.join(output_dir, outfile)

try:
    with open(output_path, "w") as f:
        f.write(json.dumps(output, indent=2))
    print("[*] All successfully saved to: {}".format(output_path))
except Exception as e:
    print("[!] Error writing to file: {}".format(e))

print("Export completed:", outfile)
