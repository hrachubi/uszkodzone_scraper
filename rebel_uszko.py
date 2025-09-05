import requests
from bs4 import BeautifulSoup
import re
import json
from pathlib import Path
from datetime import datetime, timezone


URL = "https://www.rebel.pl/promocje/1066-produkty-uszkodzone"
STATE_FILE = Path("rebel_uszkodzone_seen.json")

def extract_id_from_url(url: str):
    m = re.search(r"-(\d+)\.html?$", url)
    return m.group(1) if m else None

def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"seen_ids": [], "last_check": None}

def save_state(ids):
    payload = {
        "seen_ids": sorted(ids, key=lambda x: int(x)),
        "last_check": datetime.now(timezone.utc).isoformat()
    }
    STATE_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

def fetch_products():
    resp = requests.get(URL, headers={"User-Agent": "Mozilla/5.0"})
    soup = BeautifulSoup(resp.text, "html.parser")
    products = []
    for a in soup.select("a[href]"):
        href = a["href"]
        if "uszkodzony" in href and href.endswith(".html"):
            pid = extract_id_from_url(href)
            if pid:
                title = a.get_text(strip=True) or f"Produkt {pid}"
                url = href if href.startswith("http") else "https://www.rebel.pl" + href
                products.append({"id": pid, "url": url, "title": title})
    return products

def main():
    state = load_state()
    seen_ids = set(state.get("seen_ids", []))
    products = fetch_products()
    current_ids = {p["id"] for p in products}

    # Nowe produkty
    new = [p for p in products if p["id"] not in seen_ids]

    print(f"[{datetime.now().isoformat(timespec='seconds')}] "
          f"Znaleziono {len(products)} produktów, nowych: {len(new)}")

    for p in new:
        print(f"NOWY: {p['id']} | {p['title']} | {p['url']}")

    # Zapisz stan
    save_state(seen_ids.union(current_ids))

if __name__ == "__main__":
    main()
