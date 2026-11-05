"""
Message Batches for one-shot calls (the validator): half price, results within 24h.

The batch id is saved before waiting, so a run that's interrupted (Ctrl-C, a
dropped SSH session) picks the same batch back up on the next invocation instead
of paying for it twice.
"""
from __future__ import annotations
import json
import time
from pathlib import Path

from .llm import Reply, reply_from_message

POLL_SECONDS = 30


def run_batch(backend, prompts: dict[str, str], max_tokens: int, state: Path, log,
              poll: float = POLL_SECONDS, sleep=time.sleep) -> dict[str, Reply | str]:
    """prompts: custom_id -> user prompt. Returns custom_id -> Reply, or an error
    string for a request that failed. Ids missing from the result weren't run."""
    batches = backend.client.messages.batches
    if state.exists():
        bid = json.loads(state.read_text())["batch_id"]
        log(f"  picking up batch {bid} from {state.name}")
    else:
        reqs = [{"custom_id": k,
                 "params": backend.params("", [{"role": "user", "content": p}], max_tokens)}
                for k, p in prompts.items()]
        bid = batches.create(requests=reqs).id
        state.write_text(json.dumps({"batch_id": bid, "ids": sorted(prompts)}))
        log(f"  submitted batch {bid} ({len(reqs)} request(s)); safe to Ctrl-C and "
            "rerun the same command later")
    while True:
        b = batches.retrieve(bid)
        if b.processing_status == "ended":
            break
        c = b.request_counts
        log(f"  batch {bid}: {c.processing} processing, {c.succeeded} done, "
            f"{c.errored} errored")
        sleep(poll)
    out: dict[str, Reply | str] = {}
    for r in batches.results(bid):
        res = r.result
        if res.type == "succeeded":
            out[r.custom_id] = reply_from_message(res.message)
        elif res.type == "errored":
            err = getattr(res.error, "error", res.error)
            out[r.custom_id] = (f"BatchError: {getattr(err, 'type', 'error')}: "
                                f"{str(getattr(err, 'message', ''))[:200]}")
        else:   # canceled or expired: never ran, so it's retried next time
            out[r.custom_id] = f"BatchError: {res.type}"
    state.unlink()
    return out
