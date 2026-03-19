import json

def load_ghidra_json(path):
    with open(path, "r") as f:
        return json.load(f)

def extract_functions(json_data):
    return json_data.get("functions", {})

def simplify_cfg(cfg):
    # keep only edges between node ids
    return [{"from": e["from"], "to": e["to"]} for e in cfg.get("edges", [])]

def preprocess_function(name, func):
    return {
        "name": name,
        "asm": func.get("asm", []),
        "decomp": func.get("decomp", ""),
        "cfg": simplify_cfg(func.get("cfg", {})),
        "calls": func.get("callgraph", {}).get("calls", []),
        "imports": func.get("imports", []),
        "strings": func.get("strings", [])
    }

def preprocess_json(path):
    raw = load_ghidra_json(path)
    funcs = extract_functions(raw)
    return {
        "binary": raw.get("binary", ""),
        "functions": {
            name: preprocess_function(name, func)
            for name, func in funcs.items()
        }
    }
