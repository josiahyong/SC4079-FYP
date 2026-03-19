from openai import OpenAI
import json
from typing import Dict
import config
from prompts import make_function_prompt
# from schema import validate_output

# Configure OpenAI client (Ollama)
client = OpenAI(base_url=config.OPENAI_API_BASE, api_key="ollama")

def call_qwen(prompt: str) -> Dict:
    """
    Calls the Qwen model via Ollama using OpenAI API compat.
    """
    response = client.chat.completions.create(
        model=config.QWEN_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.6,
        max_tokens=32768
    )

    text = response.choices[0].message.content
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise RuntimeError(f"Invalid JSON from LLM:\n{text}")

def analyze_binary(bin_json):
    prompt = make_function_prompt(bin_json)
    result = call_qwen(prompt)
    # validate_output(result)
    return result
