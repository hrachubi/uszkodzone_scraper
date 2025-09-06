#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rebel.pl 'Produkty uszkodzone' scraper via Algolia API
- Queries Algolia index used by rebel.pl category
- Paginates through all pages and collects product hits
- Persists seen ids to JSON state file
- Prints newly seen products since previous run

ENV:
  REBEL_STATE_FILE (optional) - path to JSON state file
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ---------- CONFIG (fill from DevTools) ----------

# 1) From request headers in DevTools (x-algolia-application-id / x-algolia-api-key)
# ---------- CONFIG (from DevTools) ----------

ALGOLIA_APP_ID = "WN65FGR86G"
ALGOLIA_API_KEY = "MGM2M2I3YjZjYWViZjI3YjFlMDUzZDhjOTgzOTIzOGU2NWIzYmE5NGQ4Y2Q0M2MwZWE1Y2E0N2ZkZDA5ZWQwZXZhbGlkVW50aWw9MTc1NzExNjgwMiZ1c2VyVG9rZW49aTgybGJwb2x0amgwMzBwNDRrb2JtOWdpYjk="  # search-only key

ALGOLIA_SEARCH_URL = "https://wn65fgr86g-dsn.algolia.net/1/indexes/*/queries"

ALGOLIA_INDEX = "sklep_products_production_creation_date_desc"

ALGOLIA_PARAMS_BASE = (
    "query=&hitsPerPage=36"
    "&facets=%5B%22categories%22%2C%22language%22%2C%22tags.mechanic%22%2C%22tags.theme%22%2C%22tags.skill%22%2C%22tags.epoch%22%2C%22tags.content%22%2C%22labels%22%2C%22authors%22%2C%22artists%22%2C%22publishers%22%2C%22availability%22%2C%22sleevesSize%22%2C%22sleevesColor%22%2C%22colors%22%2C%22path.level0%22%2C%22path.level1%22%2C%22path.level2%22%5D"
    "&facetFilters=%5B%5B%22availability%3Ain-stock%22%5D%2C%5B%22path.level1%3A108%7CPromocje%20%3E%201066%7CProdukty%20uszkodzone%22%5D%5D"
)


# 4) Build product URL template
BASE_URL = "https://www.rebel.pl"
PRODUCT_URL_FMT = "{base}/{category}/{name}-{id}.html"

# ---------- STATE ----------
STATE_FILE = Path(os.environ.get("REBEL_STATE_FILE", "rebel_uszkodzone_seen.json"))

# ---------- HELPERS ----------

def extract_id_from_hit(hit: dict) -> str:
    """
    Prefer 'url.id' (numeric) if present; otherwise fallback to objectID.
    """
    if isinstance(hit.get("url"), dict) and "id" in hit["url"]:
        return str(hit["url"]["id"])
    if "objectID" in hit:
        # objectID is often the same numeric id as string
        return str(hit["objectID"])
    # last resort: try to find -<digits> in a composed URL (rare)
    return ""

def build_product_url(hit: dict) -> str:
    """
    Compose product URL from hit.url fields exposed by Algolia payload.
    Expected: hit["url"] = {"category":"promocje", "name":"pstryk-uszkodzony", "id":2027955}
    """
    u = hit.get("url") or {}
    category = u.get("category", "promocje")
    name = u.get("name", "")
    pid = extract_id_from_hit(hit)
    return PRODUCT_URL_FMT.format(base=BASE_URL, category=category, name=name, id=pid)

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seen_ids": [], "last_check": None}

def save_state(ids) -> None:
    payload = {
        "seen_ids": sorted({*ids}, key=lambda x: int(x)),
        "last_check": datetime.now(timezone.utc).isoformat(),
    }
    STATE_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

# ---------- ALGOLIA QUERY ----------

def query_algolia_page(session: requests.Session, page: int) -> dict:
    """
    Executes a single Algolia 'multiple queries' call for one page of the category.
    Returns the json dict for the whole response.
    """
    headers = {
        "x-algolia-application-id": ALGOLIA_APP_ID,
        "x-algolia-api-key": ALGOLIA_API_KEY,
        "content-type": "application/json",
        "accept": "application/json",
        "origin": BASE_URL,
        "referer": BASE_URL + "/",
    }
    # We send one query in the 'requests' array. You could send multiple if needed.
    payload = {
        "requests": [
            {
                "indexName": ALGOLIA_INDEX,
                "params": f"{ALGOLIA_PARAMS_BASE}&page={page}"
            }
        ]
    }
    resp = session.post(ALGOLIA_SEARCH_URL, headers=headers, json=payload, timeout=20)
    resp.raise_for_status()
    return resp.json()

def collect_all_hits() -> list:
    """
    Paginates from page=0 .. nbPages-1 collecting 'hits' into a flat list.
    """
    s = requests.Session()
    all_hits = []
    page = 0
    nb_pages = None

    while True:
        data = query_algolia_page(s, page)
        # 'results' is a list (because Algolia supports multiple queries in one call)
        results = data.get("results", [])
        if not results:
            break
        r0 = results[0]
        hits = r0.get("hits", [])
        all_hits.extend(hits)

        nb_pages = r0.get("nbPages", 0)
        page += 1
        if page >= nb_pages:
            break

    return all_hits

def hits_to_products(hits: list) -> list:
    """
    Map Algolia hits to our minimal product schema {id, url, title, price}.
    """
    products = []
    seen_ids = set()
    for h in hits:
        pid = extract_id_from_hit(h)
        if not pid or pid in seen_ids:
            continue
        url = build_product_url(h)
        title = h.get("name") or f"Produkt {pid}"
        price = h.get("currentPrice")
        price_str = f"{price:.2f} zł" if isinstance(price, (int, float)) else None
        products.append({"id": pid, "url": url, "title": title, "price": price_str})
        seen_ids.add(pid)

    # Sort by numeric id desc (heuristic: higher id ~ newer)
    products.sort(key=lambda x: int(x["id"]), reverse=True)
    return products

def send_email_new_products(new_products: list) -> None:
    """
    Send an email when new products are detected.
    Uses SMTP_* and MAIL_* environment variables.
    """
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    mail_from = os.environ.get("MAIL_FROM")
    mail_to_raw = os.environ.get("MAIL_TO")  # comma-separated
    if not (smtp_host and mail_from and mail_to_raw):
        # Missing config -> skip silently
        print("[INFO] Email not configured (set SMTP_HOST, MAIL_FROM, MAIL_TO to enable).")
        return

    recipients = [x.strip() for x in mail_to_raw.split(",") if x.strip()]
    if not recipients:
        print("[INFO] MAIL_TO is empty, skip email.")
        return

    # Build subject + body (plain text)
    subject = f"[Rebel] Nowe produkty uszkodzone: {len(new_products)}"
    lines = []
    for p in new_products:
        price = f" — {p.get('price')}" if p.get("price") else ""
        lines.append(f"- {p['title']}{price}\n  {p['url']}")
    text_body = "Wykryto nowe pozycje w kategorii 'Produkty uszkodzone':\n\n" + "\n".join(lines)

    # Create a simple MIME message (plain + minimal HTML for readability)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = ", ".join(recipients)

    msg.attach(MIMEText(text_body, "plain", "utf-8"))

    html_lines = "".join(f"<li>{p['title']}{(' — ' + p['price']) if p.get('price') else ''} "
                         f"<br><a href='{p['url']}'>{p['url']}</a></li>"
                         for p in new_products)
    html_body = f"""
    <html><body>
    <p>Wykryto nowe pozycje w kategorii <b>Produkty uszkodzone</b>:</p>
    <ul>{html_lines}</ul>
    </body></html>
    """
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    # Send via STARTTLS
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.starttls(context=context)
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(mail_from, recipients, msg.as_string())
        print(f"[INFO] Email sent to: {', '.join(recipients)}")
    except Exception as e:
        print(f"[WARN] Failed to send email: {e}")


# ---------- MAIN ----------

def main() -> int:
    # Load previous state
    state = load_state()
    seen_ids = set(state.get("seen_ids", []))

    # Fetch all hits from Algolia (all pages)
    hits = collect_all_hits()
    products = hits_to_products(hits)
    current_ids = {p["id"] for p in products}

    # Diff
    new_products = [p for p in products if p["id"] not in seen_ids]

    # Print summary
    now = datetime.now().isoformat(timespec="seconds")
    print(f"[{now}] Found {len(products)} products via Algolia, new: {len(new_products)}")

    if new_products:
        for p in new_products:
            price = f" — {p['price']}" if p.get("price") else ""
            print(f"NEW: {p['id']} | {p['title']}{price} | {p['url']}")

    # Persist updated state
    save_state(seen_ids.union(current_ids))
    send_email_new_products(new_products)       

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
