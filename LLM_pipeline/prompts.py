import json

def make_function_prompt(bin_json):
    """
    Produces a Qwen-ready prompt for a single function.
    """
    return f"""
You are an expert firmware and binary vulnerability analysis assistant. 
Your task is interprocedural taint tracking across function boundaries.
You are given the following P-Code function representation from Ghidra:

================ PROGRAM START ================
{json.dumps(bin_json, indent=2)}
================ PROGRAM END ================

Identify any security-relevant sources, sinks, and taint paths across the ENTIRE binary.
Track data flow as it passes through intermediate functions to the sink, starting from func1.

Think in English and output STRICTLY valid JSON matching this schema, with ZERO commentary:
{{
  "vulnerability_present": [yes/no]
  "vulnerability_id": [CWE-ID]
  "sources": ["function_name"],
  "sinks": ["function_name"],
  "taint_paths": [
    {{
      "source": "function_name",
      "sink": "function_name",
      "path": ["func1", "source_function", "sink_function"]
    }}
  ],
}}
"""

