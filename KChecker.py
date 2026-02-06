#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Kaspersky OpenTIP (Threat Intelligence Portal) hash checker — hardened + emoji output.

Features:
- Reads hashes from a text file (one per line)
- Queries OpenTIP:
    GET https://opentip.kaspersky.com/api/v1/search/hash?request=<hash>
    Header: x-api-key: <your_key>
- Classifies using OpenTIP "Zone":
    Green  -> SAFE
    Yellow -> SUSPICIOUS
    Red    -> MALICIOUS
    Grey   -> UNKNOWN (no data)
- If a request takes longer than --read-timeout seconds, marks TIMEOUT and continues
- Retries only on HTTP 429 with exponential backoff
- Cache to JSON (atomic writes) so re-runs resume without wasting requests
- Writes CSV even if interrupted (Ctrl+C)

ENV:
  export KASPERSKY_API_KEY="YOUR_KEY"

RUN:
  python3 KChecker.py -i hashes.txt -o kaspersky_results.csv --sleep 1 --read-timeout 120
"""

import os
import csv
import json
import time
import argparse
from typing import Dict, Any, List, Optional, Tuple

import requests
from requests.exceptions import ReadTimeout, ConnectionError, RequestException

BASE = "https://opentip.kaspersky.com/api/v1"
ENDPOINT = f"{BASE}/search/hash"
PORTAL = "https://opentip.kaspersky.com"


def emoji_verdict(verdict: str, use_emoji: bool = True) -> str:
    v = (verdict or "").upper()
    if not use_emoji:
        return v
    return {
        "SAFE": "🟢 SAFE",
        "SUSPICIOUS": "🟡 SUSPICIOUS",
        "MALICIOUS": "🔴 MALICIOUS",
        "UNKNOWN": "⚪ UNKNOWN",
        "TIMEOUT": "🟣 TIMEOUT",
        "ERROR": "🔵 ERROR",
        "CACHED": "📦 CACHED",
    }.get(v, f"⚪ {v}")


def emoji_zone(zone: str, use_emoji: bool = True) -> str:
    z = (zone or "").strip().lower()
    if not use_emoji:
        return zone
    return {
        "green": "🟢 Green",
        "yellow": "🟡 Yellow",
        "red": "🔴 Red",
        "grey": "⚪ Grey",
    }.get(z, zone)


def read_hashes(path: str) -> List[str]:
    hashes: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            h = line.strip()
            if not h or h.startswith("#"):
                continue
            hashes.append(h)

    # De-dup preserve order
    seen = set()
    out: List[str] = []
    for h in hashes:
        if h not in seen:
            out.append(h)
            seen.add(h)
    return out


def load_cache(cache_path: str) -> Dict[str, Any]:
    if not cache_path:
        return {}
    if not os.path.exists(cache_path):
        return {}
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        # If cache is corrupt, just ignore it.
        return {}


def save_cache_atomic(cache_path: str, cache: Dict[str, Any]) -> None:
    if not cache_path:
        return
    tmp = cache_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp, cache_path)
    except Exception:
        # Best-effort; don't break the run on cache write failures
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def extract_zone(payload: Any) -> str:
    if isinstance(payload, dict):
        z = payload.get("Zone") or payload.get("zone") or ""
        if isinstance(z, str):
            return z.strip()
    return ""


def classify_from_zone(zone: str) -> str:
    z = (zone or "").strip().lower()
    if z == "green":
        return "SAFE"
    if z == "yellow":
        return "SUSPICIOUS"
    if z == "red":
        return "MALICIOUS"
    if z == "grey":
        return "UNKNOWN"
    return "UNKNOWN"


def try_parse_json(resp: requests.Response) -> Tuple[Optional[Any], str]:
    ctype = (resp.headers.get("content-type") or "").lower()
    text = resp.text or ""

    if "application/json" in ctype:
        try:
            return resp.json(), "ok"
        except Exception:
            return None, "json parse failed (application/json)"

    # Sometimes content-type is wrong; try anyway if it looks like JSON
    s = text.lstrip()
    if s.startswith("{") or s.startswith("["):
        try:
            return resp.json(), f"json parsed despite content-type ({ctype})"
        except Exception:
            return None, f"non-json content-type ({ctype}); json parse failed"

    return None, f"non-json content-type ({ctype})"


def lookup_one(
    session: requests.Session,
    hash_value: str,
    api_key: str,
    connect_timeout: int,
    read_timeout: int,
    max_429_retries: int,
) -> Dict[str, Any]:
    headers = {"x-api-key": api_key}
    params = {"request": hash_value}

    backoff = 2.0
    for attempt in range(1, max_429_retries + 1):
        try:
            resp = session.get(
                ENDPOINT,
                headers=headers,
                params=params,
                timeout=(connect_timeout, read_timeout),
            )

            if resp.status_code == 429:
                if attempt == max_429_retries:
                    return {
                        "ok": False,
                        "kind": "ERROR",
                        "status": 429,
                        "error": "Rate limited (HTTP 429) - retries exhausted",
                    }
                time.sleep(backoff)
                backoff = min(backoff * 2, 120.0)
                continue

            payload, parse_note = try_parse_json(resp)
            return {
                "ok": True,
                "status": resp.status_code,
                "payload": payload,
                "parse_note": parse_note,
                "text_snippet": (resp.text or "")[:200],
            }

        except ReadTimeout:
            return {
                "ok": False,
                "kind": "TIMEOUT",
                "status": None,
                "error": f"ReadTimeout > {read_timeout}s (skipped)",
            }
        except (ConnectionError, RequestException) as e:
            return {
                "ok": False,
                "kind": "ERROR",
                "status": None,
                "error": f"{type(e).__name__}: {e}",
            }
        except Exception as e:
            return {
                "ok": False,
                "kind": "ERROR",
                "status": None,
                "error": f"UnexpectedError: {type(e).__name__}: {e}",
            }

    return {"ok": False, "kind": "ERROR", "status": None, "error": "Unexpected retry loop exit"}


def write_csv(path: str, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            for fn in fieldnames:
                r.setdefault(fn, "")
            w.writerow(r)


def main() -> None:
    ap = argparse.ArgumentParser(description="Kaspersky OpenTIP hash checker (emoji output, Zone-based).")
    ap.add_argument("-i", "--input", required=True, help="Input text file with hashes (one per line)")
    ap.add_argument("-o", "--output", default="kaspersky_results.csv", help="Output CSV file")
    ap.add_argument("--sleep", type=float, default=1.0, help="Seconds to sleep between hashes")
    ap.add_argument("--connect-timeout", type=int, default=10, help="Connect timeout seconds")
    ap.add_argument("--read-timeout", type=int, default=120, help="Skip hash if read takes longer than N seconds")
    ap.add_argument("--max-429-retries", type=int, default=6, help="Retries on HTTP 429 with backoff")
    ap.add_argument("--cache", default="kaspersky_cache.json", help="Cache JSON path (use --cache '' to disable)")
    ap.add_argument("--max", type=int, default=0, help="Max hashes to process this run (0 = all)")
    ap.add_argument("--no-emoji", action="store_true", help="Disable emoji output (plain text)")
    args = ap.parse_args()

    api_key = os.getenv("KASPERSKY_API_KEY")
    if not api_key:
        raise SystemExit("Missing KASPERSKY_API_KEY env var. Example: export KASPERSKY_API_KEY='...'\n")

    use_emoji = not args.no_emoji

    # Best-effort: set stdout to utf-8 so emojis don't crash on some consoles
    try:
        import sys
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    hashes = read_hashes(args.input)
    if args.max and args.max > 0:
        hashes = hashes[: args.max]

    if not hashes:
        raise SystemExit("No hashes found in input file.")

    cache_path = args.cache if args.cache else ""
    cache = load_cache(cache_path)

    fieldnames = ["hash", "verdict", "zone", "http_status", "parse_note", "error", "kaspersky_portal"]

    counts: Dict[str, int] = {
        "SAFE": 0,
        "SUSPICIOUS": 0,
        "MALICIOUS": 0,
        "UNKNOWN": 0,
        "TIMEOUT": 0,
        "ERROR": 0,
        "CACHED": 0,
    }

    rows: List[Dict[str, Any]] = []
    interrupted = False

    with requests.Session() as session:
        try:
            for idx, h in enumerate(hashes, start=1):
                # Cache hit
                if cache_path and h in cache and isinstance(cache[h], dict) and "row" in cache[h]:
                    row = cache[h]["row"]
                    if not isinstance(row, dict):
                        # Bad cache entry; ignore and re-query
                        pass
                    else:
                        rows.append(row)
                        counts["CACHED"] += 1
                        print(f"[{idx}/{len(hashes)}] {h} -> {emoji_verdict(row.get('verdict', ''), use_emoji)} (cached)")
                        continue

                result = lookup_one(
                    session=session,
                    hash_value=h,
                    api_key=api_key,
                    connect_timeout=args.connect_timeout,
                    read_timeout=args.read_timeout,
                    max_429_retries=args.max_429_retries,
                )

                row: Dict[str, Any] = {
                    "hash": h,
                    "verdict": "",
                    "zone": "",
                    "http_status": "",
                    "parse_note": "",
                    "error": "",
                    "kaspersky_portal": PORTAL,
                }

                if not result.get("ok"):
                    kind = result.get("kind", "ERROR")
                    if kind == "TIMEOUT":
                        row["verdict"] = "TIMEOUT"
                        counts["TIMEOUT"] += 1
                    else:
                        row["verdict"] = "ERROR"
                        counts["ERROR"] += 1

                    row["error"] = result.get("error", "Unknown error")
                    print(f"[{idx}/{len(hashes)}] {h} -> {emoji_verdict(row['verdict'], use_emoji)} ({row['error']})")

                else:
                    status = int(result.get("status") or 0)
                    row["http_status"] = status
                    row["parse_note"] = result.get("parse_note", "")

                    if status == 200:
                        payload = result.get("payload")
                        zone = extract_zone(payload)
                        verdict = classify_from_zone(zone)

                        row["zone"] = zone
                        row["verdict"] = verdict
                        counts[verdict] += 1

                        if not zone:
                            row["error"] = "200 OK but Zone missing (likely HTML/proxy/WAF; check parse_note)"

                        print(
                            f"[{idx}/{len(hashes)}] {h} -> {emoji_verdict(verdict, use_emoji)}"
                            + (f" ({emoji_zone(zone, use_emoji)})" if zone else "")
                        )

                    elif status == 404:
                        row["verdict"] = "UNKNOWN"
                        row["error"] = "Not found"
                        counts["UNKNOWN"] += 1
                        print(f"[{idx}/{len(hashes)}] {h} -> {emoji_verdict('UNKNOWN', use_emoji)} (not found)")

                    elif status == 401:
                        row["verdict"] = "ERROR"
                        row["error"] = "Unauthorized (check API key)"
                        counts["ERROR"] += 1
                        print(f"[{idx}/{len(hashes)}] {h} -> {emoji_verdict('ERROR', use_emoji)} (unauthorized)")

                    elif status == 403:
                        row["verdict"] = "ERROR"
                        row["error"] = "Forbidden (check access level / key scope)"
                        counts["ERROR"] += 1
                        print(f"[{idx}/{len(hashes)}] {h} -> {emoji_verdict('ERROR', use_emoji)} (forbidden)")

                    else:
                        row["verdict"] = "ERROR"
                        row["error"] = f"HTTP {status}: {result.get('text_snippet', '')}"
                        counts["ERROR"] += 1
                        print(f"[{idx}/{len(hashes)}] {h} -> {emoji_verdict('ERROR', use_emoji)} (HTTP {status})")

                rows.append(row)

                # Cache after each hash (so you can resume safely)
                if cache_path:
                    cache[h] = {"row": row, "saved_at": int(time.time())}
                    save_cache_atomic(cache_path, cache)

                if idx < len(hashes):
                    time.sleep(args.sleep)

        except KeyboardInterrupt:
            interrupted = True
            print("\nInterrupted (Ctrl+C). Writing CSV/cache and exiting...")

    # Always write CSV at the end
    write_csv(args.output, rows, fieldnames)

    print("\nSummary:")
    for k in ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN", "TIMEOUT", "ERROR", "CACHED"]:
        print(f"  {emoji_verdict(k, use_emoji)}: {counts[k]}")
    print(f"\nSaved: {args.output}")
    if cache_path:
        print(f"Cache: {cache_path}")
    if interrupted:
        print("Note: Run again with the same cache to resume without re-querying.")


if __name__ == "__main__":
    main()
