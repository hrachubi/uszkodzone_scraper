#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rebel.pl 'Produkty uszkodzone' scraper (requests + BeautifulSoup)
- Fetches the damaged-products category page
- Extracts product links/ids
- Persists seen ids to a JSON state file
- Prints new products since the previous run

Environment:
  REBEL_STATE_FILE (optional) - path to JSON state file
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# ---------- Config ----------
CATEGORY_URL = "https://www.rebel.pl/promocje/1066-produkty-uszkodzone"
BASE = "{u.scheme}://{u.netloc}".format(u=urlparse(CATEGORY_URL))
STATE_FILE = Path(os.environ.get("REBEL_STATE_FILE", "rebel_uszkodzone_seen.json"))

# Network settings
TIMEOUT = 20  # seconds
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# ---------- Helpers ----------

def extract_id_from_url(url: str):
    """
    Grab trailing numeric id from product URL pattern ...-<id>.html
    """
    m = re.search(r"-(\d+)\.html?$", url)
    return m.group(1) if m else None


def normalize_url(href: str) -> str:
    """
    Build absolute URL for relative links.
    """
    if href.startswith("//"):
        return "https:" + href
    return urljoin(BASE, href)


def load_state() -> dict:
    """
    Load state JSON. If missing/corrupted, return default structure.
    """
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seen_ids": [], "last_check": None}


def save_state(ids) -> None:
    """
    Save state JSON (sorted unique ids + timestamp).
    """
    payload = {
        "seen_ids": sorted({*ids}, key=lambda x: int(x)),
        "last_check": datetime.now(timezone.utc).isoformat(),
    }
    STATE_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def fetch_category_html() -> str:
    """
    Fetch category page HTML with a reasonable User-Agent and timeout.
    """
    headers = {"User-Agent": USER_AGENT}
    resp = requests.get(CATEGORY_URL, headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.text


def parse_products(html: str):
    """
    Parse product anchors from category HTML.
    We consider anchors that contain 'uszkodzony' and end with .html and have a trailing numeric id.
    Returns list of dicts: {id, url, title}
    """
    soup = BeautifulSoup(html, "html.parser")
    found = []
    seen_urls = set()

    for a in soup.select("a[href]"):
        href = a.get("href", "")
        if "uszkodzony" not in href or not href.endswith(".html"):
            continue
        abs_url = normalize_url(href)
        if abs_url in seen_urls:
            continue
        pid = extract_id_from_url(abs_url)
        if not pid:
            continue

        title = a.get_text(strip=True) or f"Produkt {pid}"
        found.append({"id": pid, "url": abs_url, "title": title})
        seen_urls.add(abs_url)

    # Sort by numeric id desc (bigger id often == newer listing)
    found.sort(key=lambda x: int(x["id"]), reverse=True)
    return found


def main() -> int:
    # Load previous state
    state = load_state()
    seen_ids = set(state.get("seen_ids", []))

    # Fetch + parse
    html = fetch_category_html()
    products = parse_products(html)
    current_ids = {p["id"] for p in products}

    # Diff
    new_products = [p for p in products if p["id"] not in seen_ids]

    # Print summary
    now = datetime.now().isoformat(timespec="seconds")
    print(f"[{now}] Found {len(products)} products, new: {len(new_products)}")

    if new_products:
        for p in new_products:
            print(f"NEW: {p['id']} | {p['title']} | {p['url']}")

    # Persist updated state
    save_state(seen_ids.union(current_ids))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
