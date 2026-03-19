import glob
import json
from preprocess import preprocess_json
from analyze import analyze_binary

EXPORTS = "./exports/*.json"
OUTPUT_DIR = "./temp"

import os
os.makedirs(OUTPUT_DIR, exist_ok=True)

for i in range(8,10):
    for ghidra_file in glob.glob(EXPORTS):
        data = preprocess_json(ghidra_file)
        binary_name = data.get("binary", os.path.basename(ghidra_file))

        print(f"Analyzing {binary_name}...")
        
        # Pass the ENTIRE binary structure for interprocedural analysis
        analysis_result = analyze_binary(data)
        
        results = {
            "binary": binary_name,
            "analysis": analysis_result
        }

        outpath = os.path.join(f"{OUTPUT_DIR}/{i+1}", f"{binary_name}_cwe_llm.json")
        with open(outpath, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Wrote analysis to {outpath}\n")