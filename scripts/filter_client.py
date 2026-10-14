"""Minimal OpenAI-compatible client for the Deucalion Ollama server.

Same shape as aegis-mvp-kg/kg/eval/llm.py (stdlib only, POST to
/v1/chat/completions, no auth header), kept separate so this repo does not
depend on the other project's layout. Ollama on a compute node listens on
127.0.0.1:$PORT with no authentication, so there is no key to manage here.
"""

import json
import time
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://127.0.0.1:11434"

SCHEMA = {
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "why": {"type": "string"},
                },
                "required": ["id", "why"],
            },
        }
    },
    "required": ["candidates"],
}


def chat(messages, model, base_url=DEFAULT_BASE_URL, temperature=0.0,
         timeout=600, json_schema=None, seed=42, retries=3):
    """One completion. Returns (content, usage) or raises."""
    body = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "seed": seed,
        "options": {"num_ctx": 65536},
    }
    if json_schema is not None:
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "decision", "schema": json_schema},
        }
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/v1/chat/completions", data=data,
        headers={"Content-Type": "application/json"},
    )
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read())
            content = payload["choices"][0]["message"]["content"]
            return content, payload.get("usage", {})
        except Exception as e:          # noqa: BLE001 — surface after retries
            last = e
            print(f"    [retry {attempt + 1}/{retries}] {type(e).__name__}: {e}",
                  flush=True)
            time.sleep(10 * (attempt + 1))
    raise RuntimeError(f"chat failed after {retries} attempts: {last}")


def extract_json(text):
    """Pull a JSON object out of a response that may be fenced or chatty."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"no JSON object in response: {text[:200]!r}")
    return json.loads(text[start:end + 1])


def warm_up(model, base_url=DEFAULT_BASE_URL, attempts=5, timeout=180):
    """Load the weights. First call costs ~90-120s and must not be a real one."""
    for i in range(attempts):
        try:
            t0 = time.time()
            chat([{"role": "user", "content": "ping"}], model,
                 base_url=base_url, timeout=timeout, retries=1)
            print(f"warm_up OK after {time.time() - t0:.1f}s", flush=True)
            return True
        except Exception as e:          # noqa: BLE001
            print(f"warm_up attempt {i + 1}/{attempts}: {type(e).__name__}: {e}",
                  flush=True)
            time.sleep(20)
    return False


def wait_until_up(base_url=DEFAULT_BASE_URL, attempts=30, delay=10):
    """Poll until the Ollama server answers /v1/models."""
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(base_url.rstrip("/") + "/v1/models",
                                        timeout=10):
                return True
        except Exception:               # noqa: BLE001
            time.sleep(delay)
    return False