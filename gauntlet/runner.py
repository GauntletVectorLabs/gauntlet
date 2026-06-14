"""Framework-agnostic runner.

Talks to any agent exposed over HTTP that accepts a JSON body and returns text
or JSON. No SDK lock-in: if your agent speaks HTTP, Gauntlet can test it.
"""

import json
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional


@dataclass
class Result:
    probe_id: str
    category: str
    message: str
    should_refuse: bool
    status: Optional[int]
    latency_ms: float
    response_text: str
    error: Optional[str]
    notes: str = ""
    tags: tuple = ()
    transcript: tuple = ()   # for multi-turn probes: ("user: ...", "assistant: ...", ...)
    trace: tuple = ()        # tool calls the agent reported: ({"tool":..., "args":...}, ...)


def _extract_text(raw_body: str, response_field: str) -> str:
    """Pull the agent's reply out of the response body.

    Tries JSON first (using the configured field, with common fallbacks),
    then falls back to the raw body.
    """
    try:
        data = json.loads(raw_body)
    except (json.JSONDecodeError, ValueError):
        return raw_body
    if isinstance(data, dict):
        for key in (response_field, "response", "output", "message", "content", "text", "reply"):
            if key in data and isinstance(data[key], str):
                return data[key]
        return json.dumps(data)
    return str(data)


def _extract_trace(raw_body, trace_field):
    """Pull a list of tool-call records out of the response body, if present.

    Accepts a JSON body with a `trace` (configurable) field that is a list of
    objects like {"tool": "issue_refund", "args": {...}}. Tolerant of `name`/
    `tool_name` aliases. Returns a tuple (possibly empty).
    """
    if not trace_field:
        return ()
    try:
        data = json.loads(raw_body)
    except (json.JSONDecodeError, ValueError):
        return ()
    if not isinstance(data, dict):
        return ()
    raw = data.get(trace_field)
    if not isinstance(raw, list):
        return ()
    out = []
    for item in raw:
        if isinstance(item, dict):
            tool = item.get("tool") or item.get("name") or item.get("tool_name") or ""
            out.append({"tool": str(tool), "args": item.get("args", item.get("arguments"))})
        elif isinstance(item, str):
            out.append({"tool": item, "args": None})
    return tuple(out)


def send_one(target_url, probe, request_field, response_field, timeout, extra_headers, trace_field=None):
    payload = json.dumps({request_field: probe.message}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    headers.update(extra_headers or {})
    req = urllib.request.Request(target_url, data=payload, headers=headers, method="POST")
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            latency = (time.time() - start) * 1000.0
            return Result(
                probe_id=probe.id,
                category=probe.category,
                message=probe.message,
                should_refuse=probe.should_refuse,
                status=resp.status,
                latency_ms=latency,
                response_text=_extract_text(body, response_field),
                error=None,
                notes=probe.notes,
                tags=probe.tags,
                trace=_extract_trace(body, trace_field),
            )
    except urllib.error.HTTPError as e:
        latency = (time.time() - start) * 1000.0
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return Result(
            probe.id, probe.category, probe.message, probe.should_refuse,
            e.code, latency, body, f"HTTP {e.code}", probe.notes, probe.tags,
        )
    except Exception as e:  # timeout, connection refused, etc.
        latency = (time.time() - start) * 1000.0
        return Result(
            probe.id, probe.category, probe.message, probe.should_refuse,
            None, latency, "", f"{type(e).__name__}: {e}", probe.notes, probe.tags,
        )


def _post(target_url, body_obj, timeout, extra_headers):
    payload = json.dumps(body_obj).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    headers.update(extra_headers or {})
    req = urllib.request.Request(target_url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def send_conversation(target_url, probe, request_field, response_field, timeout,
                      extra_headers, history_field=None, trace_field=None):
    """Drive a multi-turn probe turn-by-turn; grade the FINAL reply.

    If `history_field` is set, the running transcript (role/content list) is sent
    alongside each turn so stateless agents can use it; agents with their own
    session can ignore it.
    """
    history = []          # [{"role": "user"/"assistant", "content": ...}]
    transcript = []       # ["user: ...", "assistant: ...", ...]
    status, error, text, last_raw = None, None, "", ""
    start = time.time()
    for turn in probe.turns:
        body = {request_field: turn}
        if history_field:
            body[history_field] = list(history)
        try:
            status, raw = _post(target_url, body, timeout, extra_headers)
            last_raw = raw
            text = _extract_text(raw, response_field)
            error = None
        except urllib.error.HTTPError as e:
            status = e.code
            text = e.read().decode("utf-8", errors="replace") if e.fp else ""
            error = f"HTTP {e.code}"
            transcript.append(f"user: {turn}")
            break
        except Exception as e:  # timeout, refused, etc.
            status, error, text = None, f"{type(e).__name__}: {e}", ""
            transcript.append(f"user: {turn}")
            break
        history.append({"role": "user", "content": turn})
        history.append({"role": "assistant", "content": text})
        transcript.append(f"user: {turn}")
        transcript.append(f"assistant: {text}")
    latency = (time.time() - start) * 1000.0
    return Result(
        probe_id=probe.id, category=probe.category,
        message=probe.turns[-1] if probe.turns else "",
        should_refuse=probe.should_refuse, status=status, latency_ms=latency,
        response_text=text, error=error, notes=probe.notes, tags=probe.tags,
        transcript=tuple(transcript), trace=_extract_trace(last_raw, trace_field),
    )


def run_suite(target_url, probes, request_field="message", response_field="response",
              timeout=20.0, concurrency=8, extra_headers=None, history_field=None,
              trace_field=None):
    results = []

    def _dispatch(p):
        if hasattr(p, "turns"):   # MultiTurnProbe
            return send_conversation(target_url, p, request_field, response_field,
                                     timeout, extra_headers, history_field, trace_field)
        return send_one(target_url, p, request_field, response_field, timeout,
                        extra_headers, trace_field)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_dispatch, p) for p in probes]
        for f in futures:
            results.append(f.result())
    # Preserve probe order for stable reports.
    order = {p.id: i for i, p in enumerate(probes)}
    results.sort(key=lambda r: order.get(r.probe_id, 0))
    return results
