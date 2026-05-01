#!/usr/bin/env python3
"""NanoHunter - Cyber Security Intelligence Feed"""

import json
import os
import re
import time
import hashlib
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

SETTINGS_FILE = DATA_DIR / "settings.json"
FEEDS_CACHE_FILE = DATA_DIR / "feeds_cache.json"
BOOKMARKS_FILE = DATA_DIR / "bookmarks.json"
DAILY_LOG_FILE = DATA_DIR / "daily_log.json"

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()

DEFAULT_SETTINGS = {
    "language": "Hebrew",
    "vulnerabilities": ["XSS", "SQLi", "SSRF"],
    "max_daily": 5,
    "ai_enabled": False,
    "theme": "dark"
}

VULNERABILITY_TYPES = [
    "XSS", "SQLi", "SSRF", "RCE", "LFI", "XXE", "IDOR",
    "CSRF", "SSTI", "Open Redirect", "Business Logic",
    "Account Takeover", "PII Exposure", "Broken Auth",
    "Insecure Deserialization", "Path Traversal", "CORS Misconfiguration",
    "GraphQL Injection", "JWT Vulnerabilities", "OAuth Flaws",
    "Race Conditions", "Mass Assignment", "Prototype Pollution",
    "CRLF Injection", "ReDoS", "Subdomain Takeover",
    "Cache Poisoning", "Request Smuggling", "SAML Vulnerabilities",
    "WebSocket Security"
]

MEDIUM_REPORT_KEYWORDS = [
    "report",
    "writeup",
    "write-up",
    "write up",
    "walkthrough",
    "postmortem",
    "case study",
    "how i hacked",
    "i hacked",
    "account takeover",
    "responsible disclosure",
    "disclosure",
    "bug bounty",
    "bounty report",
    "bounty hunting",
    "poc",
    "proof of concept",
    "vulnerability report",
    "security research",
    "ctf writeup",
]

MEDIUM_SECURITY_KEYWORDS = [
    "xss", "sqli", "ssrf", "idor", "rce", "csrf", "xxe", "lfi", "open redirect",
    "auth bypass", "broken authentication", "race condition", "privilege escalation",
    "hackerone", "bugcrowd", "intigriti", "ctf", "owasp", "exploit",
]

MEDIUM_NEGATIVE_KEYWORDS = [
    "travel", "food", "recipe", "marketing", "startup pitch", "fitness",
    "music", "movie", "crypto trading", "fashion", "politics",
]

# RSS/Atom feed sources
FEED_SOURCES = [
    {
        "name": "NVD Recent CVEs",
        "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
        "type": "rss"
    },
    {
        "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml",
        "type": "rss"
    },
    {
        "name": "PortSwigger Research",
        "url": "https://portswigger.net/research/rss",
        "type": "rss"
    },
    {
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "type": "atom"
    },
    {
        "name": "HackerOne Disclosed",
        "url": "https://hackerone.com/hacktivity.rss",
        "type": "rss"
    },
    {
        "name": "Snyk Vulnerability DB",
        "url": "https://security.snyk.io/rss.xml",
        "type": "rss"
    },
    {
        "name": "Medium Cybersecurity",
        "url": "https://medium.com/feed/tag/cybersecurity",
        "type": "rss"
    },
    {
        "name": "Medium Bug Bounty",
        "url": "https://medium.com/feed/tag/bug-bounty",
        "type": "rss"
    },
    {
        "name": "Medium Hacking",
        "url": "https://medium.com/feed/tag/hacking",
        "type": "rss"
    },
    {
        "name": "Medium Penetration Testing",
        "url": "https://medium.com/feed/tag/penetration-testing",
        "type": "rss"
    },
    {
        "name": "Medium Web Security",
        "url": "https://medium.com/feed/tag/web-security",
        "type": "rss"
    },
    {
        "name": "Medium CTF",
        "url": "https://medium.com/feed/tag/ctf",
        "type": "rss"
    }
]

def load_json(path, default):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default

def save_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def get_settings():
    s = load_json(SETTINGS_FILE, {})
    merged = {**DEFAULT_SETTINGS, **s}
    if "ai_enabled" not in s:
        merged["ai_enabled"] = bool(get_anthropic_api_key(merged))
    return merged

def get_anthropic_api_key(settings=None):
    # Environment variable has priority; fallback to saved UI setting.
    if ANTHROPIC_API_KEY:
        return ANTHROPIC_API_KEY
    if settings is None:
        settings = get_settings()
    return str(settings.get("api_key", "")).strip()

def save_settings(settings):
    save_json(SETTINGS_FILE, settings)

def get_bookmarks():
    return load_json(BOOKMARKS_FILE, [])

def get_daily_log():
    return load_json(DAILY_LOG_FILE, {"date": "", "count": 0, "ids": []})

def update_daily_log(item_id):
    log = get_daily_log()
    today = datetime.now().strftime("%Y-%m-%d")
    if log.get("date") != today:
        log = {"date": today, "count": 0, "ids": []}
    log["count"] += 1
    log["ids"].append(item_id)
    save_json(DAILY_LOG_FILE, log)

def check_daily_limit():
    settings = get_settings()
    log = get_daily_log()
    today = datetime.now().strftime("%Y-%m-%d")
    if log.get("date") != today:
        return 0, settings["max_daily"]
    return log["count"], settings["max_daily"]

def fetch_feed(source):
    """Fetch and parse RSS/Atom feed"""
    items = []
    try:
        req = urllib.request.Request(
            source["url"],
            headers={"User-Agent": "NanoHunter/1.0 Security Research Tool"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read()
        root = ET.fromstring(content)
        ns = {}
        tag = root.tag
        if "atom" in tag or tag == "{http://www.w3.org/2005/Atom}feed":
            # Atom feed
            atom_ns = "http://www.w3.org/2005/Atom"
            for entry in root.findall(f"{{{atom_ns}}}entry"):
                title_el = entry.find(f"{{{atom_ns}}}title")
                link_el = entry.find(f"{{{atom_ns}}}link")
                summary_el = entry.find(f"{{{atom_ns}}}summary") or entry.find(f"{{{atom_ns}}}content")
                updated_el = entry.find(f"{{{atom_ns}}}updated") or entry.find(f"{{{atom_ns}}}published")
                title = title_el.text if title_el is not None else "No title"
                link = link_el.get("href", "") if link_el is not None else ""
                summary = summary_el.text if summary_el is not None else ""
                date_str = updated_el.text if updated_el is not None else ""
                full_text = f"{title} {summary or ''}"
                items.append({
                    "id": hashlib.md5(f"{title}{link}".encode()).hexdigest()[:12],
                    "title": title,
                    "link": link,
                    "summary": clean_html(summary or ""),
                    "date": parse_date(date_str),
                    "source": source["name"],
                    "vuln_types": detect_vuln_types(full_text),
                    "bounty_usd": extract_bounty_amount(full_text),
                })
        else:
            # RSS feed
            channel = root.find("channel") or root
            for item in channel.findall("item"):
                title_el = item.find("title")
                link_el = item.find("link")
                desc_el = item.find("description")
                date_el = item.find("pubDate") or item.find("dc:date")
                title = title_el.text if title_el is not None else "No title"
                link = link_el.text if link_el is not None else ""
                desc = desc_el.text if desc_el is not None else ""
                date_str = date_el.text if date_el is not None else ""
                full_text = f"{title} {desc or ''}"
                items.append({
                    "id": hashlib.md5(f"{title}{link}".encode()).hexdigest()[:12],
                    "title": title,
                    "link": link,
                    "summary": clean_html(desc or ""),
                    "date": parse_date(date_str),
                    "source": source["name"],
                    "vuln_types": detect_vuln_types(full_text),
                    "bounty_usd": extract_bounty_amount(full_text),
                })
    except Exception as e:
        print(f"Feed error {source['name']}: {e}")
    return items

def clean_html(text):
    """Strip HTML tags"""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:500]

def parse_date(date_str):
    """Try to parse various date formats"""
    if not date_str:
        return datetime.now().isoformat()
    formats = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt).isoformat()
        except Exception:
            pass
    return datetime.now().isoformat()

def detect_vuln_types(text):
    """Detect vulnerability types mentioned in text"""
    text_lower = text.lower()
    found = []
    mapping = {
        "XSS": ["xss", "cross-site scripting", "cross site scripting"],
        "SQLi": ["sql injection", "sqli", "sql-injection"],
        "SSRF": ["ssrf", "server-side request forgery"],
        "RCE": ["rce", "remote code execution", "code execution"],
        "LFI": ["lfi", "local file inclusion"],
        "XXE": ["xxe", "xml external entity"],
        "IDOR": ["idor", "insecure direct object"],
        "CSRF": ["csrf", "cross-site request forgery"],
        "SSTI": ["ssti", "server-side template injection", "template injection"],
        "Open Redirect": ["open redirect", "url redirect"],
        "Business Logic": ["business logic", "logic flaw"],
        "Account Takeover": ["account takeover", "ato"],
        "PII Exposure": ["pii", "personal data", "data exposure", "data leak"],
        "Broken Auth": ["broken auth", "authentication bypass", "auth bypass"],
        "Path Traversal": ["path traversal", "directory traversal"],
        "CORS Misconfiguration": ["cors"],
        "JWT Vulnerabilities": ["jwt", "json web token"],
        "OAuth Flaws": ["oauth"],
        "Race Conditions": ["race condition"],
        "Cache Poisoning": ["cache poison"],
        "Request Smuggling": ["request smuggling", "http smuggling"],
        "Prototype Pollution": ["prototype pollution"],
        "Subdomain Takeover": ["subdomain takeover"],
    }
    for vuln, keywords in mapping.items():
        for kw in keywords:
            if kw in text_lower:
                found.append(vuln)
                break
    return found

def extract_bounty_amount(text):
    """Extract likely bug bounty amount in USD from text"""
    if not text:
        return None
    candidates = []
    patterns = [
        r"\$\s*([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+(?:\.[0-9]+)?)\s*([kK])?",
        r"usd\s*([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+(?:\.[0-9]+)?)\s*([kK])?",
    ]
    for pattern in patterns:
        for value_str, suffix in re.findall(pattern, text, flags=re.IGNORECASE):
            raw = value_str.replace(",", "")
            try:
                value = float(raw)
                if suffix and suffix.lower() == "k":
                    value *= 1000
                if 10 <= value <= 1_000_000:
                    candidates.append(int(value))
            except Exception:
                pass
    return max(candidates) if candidates else None

def format_bounty_amount(amount):
    if not amount:
        return "N/A"
    return f"${amount:,}"

def is_medium_report_item(item):
    if not str(item.get("source", "")).lower().startswith("medium"):
        return False
    text = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    score = 0
    if any(keyword in text for keyword in MEDIUM_REPORT_KEYWORDS):
        score += 3
    if any(keyword in text for keyword in MEDIUM_SECURITY_KEYWORDS):
        score += 2
    if item.get("bounty_usd"):
        score += 3
    if item.get("vuln_types"):
        score += 1
    if "medium.com" in str(item.get("link", "")).lower():
        score += 1
    if any(keyword in text for keyword in MEDIUM_NEGATIVE_KEYWORDS):
        score -= 3
    return score >= 3

def refresh_feeds():
    """Fetch all feeds and cache results"""
    all_items = []
    for source in FEED_SOURCES:
        items = fetch_feed(source)
        all_items.extend(items)
    # Deduplicate
    seen = set()
    unique = []
    for item in all_items:
        if item["id"] not in seen:
            seen.add(item["id"])
            unique.append(item)
    # Sort by date descending
    unique.sort(key=lambda x: x.get("date", ""), reverse=True)
    cache = {
        "updated": datetime.now().isoformat(),
        "items": unique[:200]
    }
    save_json(FEEDS_CACHE_FILE, cache)
    return cache

def get_cached_feeds():
    cache = load_json(FEEDS_CACHE_FILE, {"updated": "", "items": []})
    # Refresh if older than 2 hours
    if cache.get("updated"):
        try:
            updated = datetime.fromisoformat(cache["updated"])
            if datetime.now() - updated < timedelta(hours=2):
                return cache
        except Exception:
            pass
    return refresh_feeds()

def filter_items(items, settings):
    """Filter items by selected vulnerabilities"""
    selected = settings.get("vulnerabilities", [])
    if not selected:
        return items
    filtered = []
    for item in items:
        vuln_types = item.get("vuln_types", [])
        if any(v in selected for v in vuln_types):
            filtered.append(item)
    # If too few matches, also include recent unmatched items
    if len(filtered) < 10:
        for item in items:
            if item not in filtered:
                filtered.append(item)
            if len(filtered) >= 50:
                break
    return filtered

def is_recent(item, months=12):
    """Check if item is within the last N months"""
    try:
        dt = datetime.fromisoformat(item["date"].replace("Z", "+00:00"))
        cutoff = datetime.now(dt.tzinfo) - timedelta(days=30 * months)
        return dt > cutoff
    except Exception:
        return True

def generate_ai_summary(item, language="Hebrew", api_key=""):
    """Call Anthropic API for AI summary"""
    if not api_key:
        return None, "missing_api_key"
    lang_map = {
        "Hebrew": "עברית",
        "English": "English",
        "Arabic": "العربية",
        "Russian": "Русский",
        "French": "Français",
        "Spanish": "Español",
    }
    lang = lang_map.get(language, language)
    prompt = f"""You are a cybersecurity expert. Summarize this vulnerability/finding for a security researcher.

Title: {item['title']}
Source: {item['source']}
Content: {item['summary']}
URL: {item['link']}

Please provide a concise summary in {lang} with:
1. **What is it**: Brief explanation of the vulnerability
2. **Impact**: Who is affected and severity  
3. **PoC/Example**: A short code example or attack vector if applicable
4. **Conclusion**: Key takeaway for bug bounty hunters / pentesters

Keep it under 300 words. Use markdown formatting."""

    try:
        data = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 600,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            }
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            return result["content"][0]["text"], None
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        print(f"AI HTTP error {e.code}: {body[:500]}")
        if e.code in (401, 403):
            return None, "invalid_api_key"
        if e.code == 400 and "credit balance is too low" in body.lower():
            return None, "insufficient_credits"
        return None, f"http_{e.code}"
    except Exception as e:
        print(f"AI error: {e}")
        return None, "request_failed"

def format_date_display(date_str):
    """Format date for display"""
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        now = datetime.now(dt.tzinfo)
        diff = now - dt
        if diff.days == 0:
            hours = diff.seconds // 3600
            return f"{hours}h ago" if hours > 0 else "Just now"
        elif diff.days < 7:
            return f"{diff.days}d ago"
        elif diff.days < 30:
            weeks = diff.days // 7
            return f"{weeks}w ago"
        else:
            return dt.strftime("%b %d, %Y")
    except Exception:
        return date_str[:10] if len(date_str) >= 10 else date_str

class NanoHunterHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logging

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, status=200):
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def serve_static(self, path):
        static_dir = Path(__file__).parent / "static"
        file_path = static_dir / path.lstrip("/")
        if file_path.exists() and file_path.is_file():
            content = file_path.read_bytes()
            ext = file_path.suffix
            ct = {
                ".css": "text/css",
                ".js": "application/javascript",
                ".png": "image/png",
                ".ico": "image/x-icon"
            }.get(ext, "text/plain")
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self.send_html(get_main_html())
        elif path.startswith("/static/"):
            self.serve_static(path[7:])
        elif path == "/api/feeds":
            self.handle_feeds(params)
        elif path == "/api/settings":
            self.send_json(get_settings())
        elif path == "/api/medium-reports":
            self.handle_medium_reports(params)
        elif path == "/api/vuln-types":
            self.send_json(VULNERABILITY_TYPES)
        elif path == "/api/bookmarks":
            self.send_json(get_bookmarks())
        elif path == "/api/daily-status":
            used, limit = check_daily_limit()
            self.send_json({"used": used, "limit": limit, "remaining": limit - used})
        elif path == "/api/refresh":
            cache = refresh_feeds()
            self.send_json({"ok": True, "count": len(cache["items"]), "updated": cache["updated"]})
        elif path == "/api/summary":
            self.handle_summary(params)
        elif path == "/api/export":
            self.handle_export(params)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/settings":
            settings = get_settings()
            settings.update(data)
            if "api_key" in settings:
                settings["api_key"] = str(settings.get("api_key", "")).strip()
                if settings["api_key"]:
                    settings["ai_enabled"] = True
            save_settings(settings)
            self.send_json({"ok": True})
        elif path == "/api/bookmarks":
            bookmarks = get_bookmarks()
            item_id = data.get("id")
            if item_id and item_id not in bookmarks:
                bookmarks.append(item_id)
                save_json(BOOKMARKS_FILE, bookmarks)
            self.send_json({"ok": True, "bookmarks": bookmarks})
        elif path == "/api/bookmarks/remove":
            bookmarks = get_bookmarks()
            item_id = data.get("id")
            if item_id in bookmarks:
                bookmarks.remove(item_id)
                save_json(BOOKMARKS_FILE, bookmarks)
            self.send_json({"ok": True, "bookmarks": bookmarks})
        else:
            self.send_response(404)
            self.end_headers()

    def handle_feeds(self, params):
        settings = get_settings()
        cache = get_cached_feeds()
        items = cache.get("items", [])
        # Filter by selected vulns
        selected_vulns = params.get("vulns", [settings.get("vulnerabilities", [])])
        if isinstance(selected_vulns[0], list):
            selected_vulns = selected_vulns[0]
        else:
            selected_vulns = params.get("vulns[]", settings.get("vulnerabilities", []))
        # Apply vuln filter
        if selected_vulns:
            filtered = []
            for item in items:
                if any(v in selected_vulns for v in item.get("vuln_types", [])):
                    filtered.append(item)
            if len(filtered) < 5:
                filtered = items  # Fallback to all
        else:
            filtered = items
        # Time filter
        time_filter = params.get("time", ["all"])[0]
        if time_filter == "week":
            filtered = [i for i in filtered if is_recent(i, months=0.25)]
        elif time_filter == "month":
            filtered = [i for i in filtered if is_recent(i, months=1)]
        elif time_filter == "year":
            filtered = [i for i in filtered if is_recent(i, months=12)]
        # Search
        search = params.get("q", [""])[0].lower()
        if search:
            filtered = [i for i in filtered if search in i["title"].lower() or search in i["summary"].lower()]
        # Source filter
        source_filter = params.get("source", ["all"])[0]
        if source_filter != "all":
            filtered = [i for i in filtered if i["source"] == source_filter]
        # Bookmarks filter
        if params.get("bookmarks", ["false"])[0] == "true":
            bm = get_bookmarks()
            filtered = [i for i in filtered if i["id"] in bm]
        bookmarks = get_bookmarks()
        for item in filtered:
            item["bookmarked"] = item["id"] in bookmarks
            item["date_display"] = format_date_display(item.get("date", ""))
            item["bounty_display"] = format_bounty_amount(item.get("bounty_usd"))
        sources = list(set(i["source"] for i in items))
        self.send_json({
            "items": filtered[:100],
            "total": len(filtered),
            "updated": cache.get("updated", ""),
            "sources": sources
        })

    def handle_medium_reports(self, params):
        cache = get_cached_feeds()
        items = cache.get("items", [])
        if not any(str(i.get("source", "")).lower().startswith("medium") for i in items):
            cache = refresh_feeds()
            items = cache.get("items", [])
        filtered = [item for item in items if is_medium_report_item(item)]
        if not filtered:
            medium_all = [item for item in items if str(item.get("source", "")).lower().startswith("medium")]
            # Fallback to Medium-only feed even when report score is low, to avoid empty page.
            filtered = medium_all
        time_filter = params.get("time", ["all"])[0]
        if time_filter == "week":
            filtered = [i for i in filtered if is_recent(i, months=0.25)]
        elif time_filter == "month":
            filtered = [i for i in filtered if is_recent(i, months=1)]
        elif time_filter == "year":
            filtered = [i for i in filtered if is_recent(i, months=12)]
        search = params.get("q", [""])[0].lower()
        if search:
            filtered = [i for i in filtered if search in i["title"].lower() or search in i["summary"].lower()]
        bookmarks = get_bookmarks()
        for item in filtered:
            item["bookmarked"] = item["id"] in bookmarks
            item["date_display"] = format_date_display(item.get("date", ""))
            item["bounty_display"] = format_bounty_amount(item.get("bounty_usd"))
        bounty_known = [i.get("bounty_usd") for i in filtered if i.get("bounty_usd")]
        self.send_json({
            "items": filtered[:100],
            "total": len(filtered),
            "updated": cache.get("updated", ""),
            "known_bounties": len(bounty_known),
            "max_bounty": max(bounty_known) if bounty_known else None,
        })

    def handle_summary(self, params):
        item_id = params.get("id", [""])[0]
        cache = get_cached_feeds()
        items = cache.get("items", [])
        item = next((i for i in items if i["id"] == item_id), None)
        if not item:
            self.send_json({"error": "Not found"}, 404)
            return
        settings = get_settings()
        used, limit = check_daily_limit()
        # Check cache
        summary_cache_file = DATA_DIR / f"summary_{item_id}.json"
        if summary_cache_file.exists():
            cached = json.loads(summary_cache_file.read_text())
            self.send_json(cached)
            return
        if used >= limit:
            self.send_json({
                "error": f"Daily limit reached ({limit}/day). Resets at midnight.",
                "limit_reached": True
            })
            return
        api_key = get_anthropic_api_key(settings)
        if settings.get("ai_enabled") and api_key:
            summary, ai_error = generate_ai_summary(item, settings.get("language", "Hebrew"), api_key)
            if summary:
                update_daily_log(item_id)
                result = {"summary": summary, "item": item, "ai": True}
                save_json(summary_cache_file, result)
                self.send_json(result)
                return
            if ai_error == "invalid_api_key":
                self.send_json({
                    "error": "Invalid Anthropic API key. Please update the key in settings.",
                    "ai": False
                }, 400)
                return
            if ai_error == "insufficient_credits":
                self.send_json({
                    "error": "Anthropic API credits are too low. Please top up billing and try again.",
                    "ai": False
                }, 402)
                return
        # Fallback: structured summary from existing data
        result = {
            "summary": f"## {item['title']}\n\n**Source**: {item['source']}\n\n**Details**:\n{item['summary']}\n\n*[AI summary unavailable - add a valid Anthropic API key in settings or set ANTHROPIC_API_KEY in environment]*",
            "item": item,
            "ai": False
        }
        self.send_json(result)

    def handle_export(self, params):
        fmt = params.get("format", ["md"])[0]
        item_id = params.get("id", [""])[0]
        cache = get_cached_feeds()
        items = cache.get("items", [])
        if item_id:
            items = [i for i in items if i["id"] == item_id]
        else:
            items = items[:20]
        if fmt == "md":
            lines = ["# NanoHunter Export\n", f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"]
            for item in items:
                lines.append(f"## {item['title']}\n")
                lines.append(f"**Source**: {item['source']}  \n")
                lines.append(f"**Date**: {item.get('date_display', item.get('date', '')[:10])}  \n")
                lines.append(f"**Types**: {', '.join(item.get('vuln_types', ['General']))}  \n")
                lines.append(f"**Link**: {item['link']}  \n\n")
                lines.append(f"{item['summary']}\n\n---\n\n")
            content = "".join(lines).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=nanohunter_export.md")
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_json({"error": "Unsupported format"}, 400)


def get_main_html():
    base_dir = Path(__file__).parent
    candidates = [
        base_dir / "static" / "index.html",
        base_dir / "index.html",
    ]
    for html_path in candidates:
        if html_path.exists():
            return html_path.read_text(encoding="utf-8")
    raise FileNotFoundError("Could not locate index.html in static/ or project root.")


def run():
    port = 8888
    server = HTTPServer(("0.0.0.0", port), NanoHunterHandler)
    print(f"""
╔══════════════════════════════════════════════╗
║           NanoHunter v1.0 🎯                 ║
║   Cyber Security Intelligence Feed          ║
╠══════════════════════════════════════════════╣
║  Server: http://localhost:{port}              ║
║  Status: Running                             ║
╚══════════════════════════════════════════════╝

Set ANTHROPIC_API_KEY env variable for AI summaries.
Press Ctrl+C to stop.
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server stopped.")

if __name__ == "__main__":
    run()
