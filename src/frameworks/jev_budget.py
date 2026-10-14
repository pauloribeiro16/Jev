"""Jev spend guard: meters every system_one call and enforces a hard ceiling.

The SDK already returns usage.input_tokens / output_tokens on every response;
this module records them so a runaway loop cannot quietly drain the month.
Every TypeSafeClient in this repo is built here, so metering is unavoidable
rather than opt-in.
"""

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Tuple

from typesafe_sdk import Choice, Noul, Score, RetryPolicy, TypeSafeClient

LEDGER = Path(__file__).resolve().parent.parent.parent / "data" / "jev_ledger.jsonl"
TRACES = Path(__file__).resolve().parent.parent.parent / "data" / "jev_traces.jsonl"

# ponytail: traces hold the full payload (~10-30 KB per call). At 2k hops/day a
# month would be gigabytes, so the file keeps only the most recent calls. The
# ledger is deliberately NOT truncated: losing a spend record would break the
# budget accounting that protects the ceiling.
TRACE_LIMIT = 200

DAY = 86400
MONTH = 30 * DAY

# Calibrated from one billing sample: 172,944 tokens = $0.0066.
DEFAULT_PRICE_PER_MTOK = 0.038158


class BudgetExceeded(RuntimeError):
    """Raised before a call that would push spend past a configured ceiling."""


def _num(name: str, default: float) -> float:
    try:
        raw = os.getenv(name)
        return float(raw) if raw not in (None, "") else default
    except ValueError:
        return default


def budget_tokens() -> float:
    return _num("JEV_BUDGET_TOKENS", 5_000_000)


def budget_usd() -> float:
    return _num("JEV_BUDGET_USD", 5.00)


def price_per_mtok() -> float:
    return _num("JEV_PRICE_PER_MTOK", DEFAULT_PRICE_PER_MTOK)


def usd_of(tokens: float) -> float:
    return tokens / 1_000_000 * price_per_mtok()


def _spend(window: int) -> float:
    """Tokens recorded within the last `window` seconds.

    ponytail: re-reads the whole ledger per call (O(n)); at ~2k hops/day the
    file stays in the thousands of lines, so a counter file only earns its
    keep if a day ever runs to millions of calls.
    """
    if not LEDGER.exists():
        return 0.0
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window)).timestamp()
    total = 0.0
    for line in LEDGER.read_text(errors="ignore").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("ts", 0) >= cutoff:
            total += rec.get("tokens", 0)
    return total


def _dump(obj):
    """Questions and answers are pydantic models; model_dump gives plain JSON."""
    return obj.model_dump(mode="json") if hasattr(obj, "model_dump") else obj


def _record(site: str, resp, latency_ms: float = 0.0, state=None, questions=None) -> dict:
    usage = getattr(resp, "usage", None)
    n_in = getattr(usage, "input_tokens", None) or 0
    n_out = getattr(usage, "output_tokens", None) or 0
    rec = {
        "ts": time.time(),
        "iso": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "site": site,
        "model": getattr(resp, "model", None),
        "request_id": getattr(resp, "request_id", None),
        "input_tokens": n_in,
        "output_tokens": n_out,
        "tokens": n_in + n_out,
    }
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        f.write(json.dumps(rec) + "\n")

    answers = getattr(resp, "answers", None) or {}
    trace = {
        **rec,
        "latencyMs": round(latency_ms, 2),
        "request": {
            "state": state,
            "questions": {name: _dump(q) for name, q in (questions or {}).items()},
        },
        "response": {
            "answers": {name: _dump(a) for name, a in answers.items()},
            "usage": {"input_tokens": n_in, "output_tokens": n_out},
        },
    }
    with TRACES.open("a") as f:
        f.write(json.dumps(trace, ensure_ascii=False) + "\n")
    lines = TRACES.read_text(errors="ignore").splitlines()
    if len(lines) > TRACE_LIMIT:
        TRACES.write_text("\n".join(lines[-TRACE_LIMIT:]) + "\n")

    return rec


def check_budget(site: str = "unknown") -> None:
    """Raise BudgetExceeded if this call would breach a ceiling."""
    day = _spend(DAY)
    if day >= budget_tokens():
        raise BudgetExceeded(
            f"[{site}] daily cap reached: {day:,.0f}/{budget_tokens():,.0f} tokens. "
            "Raise JEV_BUDGET_TOKENS or wait for the window to roll."
        )
    if price_per_mtok() > 0:
        month = _spend(MONTH)
        usd = usd_of(month)
        if usd >= budget_usd():
            raise BudgetExceeded(
                f"[{site}] 30-day cap reached: ${usd:.4f}/${budget_usd():.2f} "
                f"({month:,.0f} tokens). Raise JEV_BUDGET_USD to continue."
            )


class MeteredClient:
    """Delegates to TypeSafeClient, meters usage, enforces caps."""

    def __init__(self, inner, site: str = "unknown"):
        self._inner = inner
        self.site = site
        self.last_usage = None

    def system_one(self, *args, **kwargs):
        check_budget(self.site)
        # Every call site in this repo passes state/questions by keyword, but
        # fall back to position so a future positional call is still traced.
        state = kwargs.get("state", args[0] if len(args) > 0 else None)
        questions = kwargs.get("questions", args[1] if len(args) > 1 else None)
        t0 = time.perf_counter()
        resp = self._inner.system_one(*args, **kwargs)
        self.last_usage = _record(
            self.site, resp,
            latency_ms=(time.perf_counter() - t0) * 1000,
            state=state,
            questions=questions,
        )
        return resp

    def __getattr__(self, name):
        return getattr(self._inner, name)


class MockClient:
    """Offline stand-in so the pipeline can be validated without an API key."""

    def __init__(self):
        self.calls = []
        self.site = "mock"

    def system_one(self, state=None, questions=None, **kwargs):
        self.calls.append((state, questions))
        answers = {}
        for name, q in (questions or {}).items():
            if isinstance(q, Noul):
                answers[name] = SimpleNamespace(noul=0.5)
            elif isinstance(q, Choice):
                keys = sorted(getattr(q, "criteria", {}) or {})
                answers[name] = SimpleNamespace(
                    choice=keys[0] if keys else None, confidence=0.5, probabilities={}
                )
            elif isinstance(q, Score):
                answers[name] = SimpleNamespace(score=1, legend={}, probabilities={})
        return SimpleNamespace(
            model="mock",
            usage=SimpleNamespace(input_tokens=0, output_tokens=0),
            answers=answers,
            nouls={k: v for k, v in answers.items() if hasattr(v, "noul")},
            choices={k: v for k, v in answers.items() if hasattr(v, "choice")},
            scores={k: v for k, v in answers.items() if hasattr(v, "score")},
        )


def get_client(api_key: str = None, site: str = "unknown", mock: bool = False):
    """The one place this repo builds a Jev client, so every call is metered."""
    if mock:
        return MockClient()
    key = api_key or os.getenv("API_JEV") or os.getenv("TYPESAFE_API_KEY")
    if not key:
        raise RuntimeError(
            "No Jev API key found. Set API_JEV or TYPESAFE_API_KEY in .env "
            "(see .env.example), or pass mock=True for an offline dry run."
        )
    # max_retries=1: the SDK default of 2 means a throttled (429) call can be
    # billed up to 3x, which is the cheapest way to blow a ceiling unnoticed.
    inner = TypeSafeClient(api_key=key, retry=RetryPolicy(max_retries=1))
    return MeteredClient(inner, site=site)


def _counts(window: int) -> Tuple[float, int]:
    """(tokens, calls) recorded within the last `window` seconds."""
    if not LEDGER.exists():
        return 0.0, 0
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window)).timestamp()
    total, calls = 0.0, 0
    for line in LEDGER.read_text(errors="ignore").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("ts", 0) >= cutoff:
            total += rec.get("tokens", 0)
            calls += 1
    return total, calls


def _spend(window: int) -> float:
    return _counts(window)[0]


def report() -> None:
    day, day_calls = _counts(DAY)
    month, month_calls = _counts(MONTH)
    cap = budget_tokens()
    print("Jev spend")
    print(f"  last 24h : {day:>12,.0f} tokens  (cap {cap:,.0f})  ${usd_of(day):.4f}")
    print(f"  last 30d : {month:>12,.0f} tokens          ${usd_of(month):.4f}"
          f"  (cap ${budget_usd():.2f})")
    print(f"  rate     : ${price_per_mtok():.6f} / Mtok")
    if month_calls:
        print(f"  per call : {month / month_calls:>12,.0f} tokens  "
              f"~${usd_of(month / month_calls):.6f}  ({month_calls} calls)")


def selfcheck() -> None:
    """Assert the guard meters and blocks. Keeps a silent failure from costing money."""
    import tempfile
    global LEDGER, TRACES
    original_ledger, original_traces = LEDGER, TRACES
    with tempfile.TemporaryDirectory() as tmp:
        # Redirect both files: a self-check must never pollute the real trace log.
        LEDGER = Path(tmp) / "ledger.jsonl"
        TRACES = Path(tmp) / "traces.jsonl"
        os.environ["JEV_BUDGET_TOKENS"] = "10"
        os.environ["JEV_BUDGET_USD"] = "999"
        resp = SimpleNamespace(model="m", usage=SimpleNamespace(input_tokens=4, output_tokens=6))
        client = MeteredClient(inner=None, site="selfcheck")
        client._inner = SimpleNamespace(system_one=lambda *a, **k: resp)
        check_budget("selfcheck")
        client.system_one(state={"node": "CWE-79"}, questions={"q": Noul(instructions="?")})
        assert _spend(DAY) == 10, _spend(DAY)
        traced = json.loads(TRACES.read_text().splitlines()[-1])
        assert traced["request"]["state"] == {"node": "CWE-79"}
        assert traced["request"]["questions"]["q"]["type"] == "noul"
        assert traced["tokens"] == 10
        try:
            check_budget("selfcheck")
        except BudgetExceeded:
            pass
        else:
            raise AssertionError("BudgetExceeded did not fire at the cap")
        # MockClient must satisfy the same response shape the call sites read.
        mock = MockClient()
        out = mock.system_one(state={}, questions={
            "n": Noul(instructions="?"),
            "c": Choice(instructions="?", criteria={"a": "A", "b": "B"}),
            "s": Score(instructions="?", criteria=["low", "high"]),
        })
        assert out.nouls["n"].noul == 0.5
        assert out.choices["c"].choice == "a"
        assert out.scores["s"].score == 1
    LEDGER, TRACES = original_ledger, original_traces
    print("selfcheck OK: metering, cap, trace capture, and mock all behave")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        selfcheck()
    else:
        report()