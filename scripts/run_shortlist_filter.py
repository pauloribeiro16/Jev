"""Run the shortlist filter on the big model. Executes inside the sbatch job.

Reads the prompt files produced by build_filter_prompts.py, calls the model
once per prompt, writes one JSONL line per result. Strictly sequential: one
Ollama per node, and parallel calls to it are documented to fail.
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from filter_client import SCHEMA, chat, extract_json, warm_up  # noqa: E402


def run_set(path: Path, out: Path, model: str, base_url: str, limit: int):
    prompts = json.loads(path.read_text(encoding="utf-8"))
    if limit:
        prompts = prompts[:limit]
    print(f"{path.name}: {len(prompts)} prompts", flush=True)

    ok = failed = 0
    prompt_tokens = completion_tokens = 0
    t_start = time.time()

    with out.open("a", encoding="utf-8") as sink:
        for i, item in enumerate(prompts, start=1):
            key = item.get("use_case") or item.get("technique_id")
            t0 = time.time()
            try:
                content, usage = chat(item["messages"], model,
                                      base_url=base_url, json_schema=SCHEMA)
                data = extract_json(content)
                cands = [c for c in data.get("candidates", []) if c.get("id")]
                if not cands:
                    raise ValueError("model returned no candidates")
            except Exception as e:       # noqa: BLE001 — one bad call must not kill the job
                failed += 1
                print(f"  [{i}/{len(prompts)}] {key} FAILED: {type(e).__name__}: {e}",
                      flush=True)
                sink.write(json.dumps({"key": key, "ok": False,
                                       "error": f"{type(e).__name__}: {e}"}) + "\n")
                sink.flush()
                continue

            ok += 1
            prompt_tokens += usage.get("prompt_tokens", 0)
            completion_tokens += usage.get("completion_tokens", 0)
            sink.write(json.dumps({
                "key": key,
                "title": item.get("title") or item.get("technique"),
                "ok": True,
                "candidates": cands,
            }, ensure_ascii=False) + "\n")
            sink.flush()
            top = ", ".join(c["id"] for c in cands[:4])
            print(f"  [{i}/{len(prompts)}] {key} -> {len(cands)} cands "
                  f"({time.time() - t0:.1f}s) {top}", flush=True)

    print(f"{path.name}: ok={ok} failed={failed} "
          f"tokens={prompt_tokens + completion_tokens} "
          f"elapsed={time.time() - t_start:.0f}s", flush=True)
    return ok, failed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompts", type=Path, default=Path("prompts"))
    ap.add_argument("--out", type=Path, default=Path("data/shortlists"))
    ap.add_argument("--model", default="qwen3.8:27b")
    ap.add_argument("--base-url", default="http://127.0.0.1:11434")
    ap.add_argument("--limit", type=int, default=0, help="0 = all prompts")
    ap.add_argument("--skip-warmup", action="store_true")
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    if not args.skip_warmup:
        print("warming up model...", flush=True)
        if not warm_up(args.model, args.base_url):
            print("WARMUP FAILED — aborting before burning walltime", flush=True)
            sys.exit(1)

    total_ok = total_fail = 0
    for path in sorted(args.prompts.glob("*.json")):
        out = args.out / (path.stem + ".jsonl")
        ok, fail = run_set(path, out, args.model, args.base_url, args.limit)
        total_ok += ok
        total_fail += fail

    print(f"TOTAL ok={total_ok} failed={total_fail}", flush=True)
    # Partial results are still usable; only a total wipeout is a failure.
    sys.exit(0 if total_ok else 1)


if __name__ == "__main__":
    main()