from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import httpx
import asyncio
import os
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# ===== CORS =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://proof-ai-one.vercel.app",
        'http://127.0.0.1:5500',      
        'http://localhost:5500',       
        'http://localhost:3000',      
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== CONFIG — Đọc từ environment variables =====
VT_KEY      = os.environ.get("VIRUSTOTAL_API_KEY", "")
URLSCAN_KEY = os.environ.get("URLSCAN_API_KEY", "")
IPINFO_TOK  = os.environ.get("IPINFO_TOKEN", "")

TEXT_API = "https://text-service-glgj.onrender.com/detect"

# ===== MODELS =====
class URLRequest(BaseModel):
    url: str

class DomainRequest(BaseModel):
    domain: str

class URLScanRequest(BaseModel):
    url: str

# ===== UTILS =====
def extract_domain(url: str) -> str:
    return urlparse(url).netloc

async def fetch_html(url: str):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml",
    }
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(url, headers=headers)
            return {"success": True, "html": r.text[:5000], "status": r.status_code}
    except httpx.TimeoutException:
        return {"success": False, "error": "Timeout khi fetch URL", "status": 408}
    except httpx.RequestError:
        return {"success": False, "error": "Không thể kết nối tới URL", "status": 500}
    except Exception as e:
        return {"success": False, "error": str(e), "status": 500}

async def analyze_text(content: str):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(TEXT_API, json={"content": content})
            if r.status_code != 200:
                return {"success": False, "error": "AI service lỗi"}
            return {"success": True, "data": r.json()}
    except httpx.TimeoutException:
        return {"success": False, "error": "AI timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ===== HEALTH =====
@app.get("/health")
def health():
    return {
        "status": "ok",
        "virustotal": bool(VT_KEY),
        "urlscan": bool(URLSCAN_KEY),
        "ipinfo": bool(IPINFO_TOK),
    }

# ===== VIRUSTOTAL — Proxy endpoints =====

@app.post("/api/vt-scan")
async def vt_scan(req: URLRequest):
    """
    Scan URL qua VirusTotal với polling.
    Frontend gọi endpoint này thay vì gọi VT trực tiếp (tránh CORS + bảo mật key).
    """
    if not VT_KEY:
        return {"ok": False, "error": "VIRUSTOTAL_API_KEY chưa được cấu hình"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # 1. Submit URL
            submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": VT_KEY},
                data={"url": req.url},
            )
            submit.raise_for_status()
            analysis_id = submit.json()["data"]["id"]

        # 2. Poll cho đến khi completed (tối đa 10 lần × 3s)
        MAX_POLLS = 10
        for attempt in range(MAX_POLLS):
            await asyncio.sleep(3)
            async with httpx.AsyncClient(timeout=15) as client:
                result = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers={"x-apikey": VT_KEY},
                )
                result.raise_for_status()
                data = result.json()

            status = data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = data["data"]["attributes"].get("stats", {})
                total = sum(stats.values()) or 1
                mal   = stats.get("malicious",  0)
                sus   = stats.get("suspicious", 0)
                return {
                    "ok":           True,
                    "malicious":    mal,
                    "suspicious":   sus,
                    "harmless":     stats.get("harmless",   0),
                    "undetected":   stats.get("undetected", 0),
                    "totalEngines": total,
                    "threatScore":  round((mal + sus * 0.5) / total * 100),
                }

            if status not in ("queued", "in-progress"):
                break

        return {"ok": False, "error": "VT analysis không hoàn tất sau thời gian chờ"}

    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/vt-domain")
async def vt_domain(req: DomainRequest):
    """
    Lấy thông tin domain từ VirusTotal.
    """
    if not VT_KEY:
        return {"ok": False, "error": "VIRUSTOTAL_API_KEY chưa được cấu hình"}

    try:
        registrable = ".".join(req.domain.split(".")[-2:])
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{registrable}",
                headers={"x-apikey": VT_KEY},
            )
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})

        import datetime
        creation_date = None
        if attrs.get("creation_date"):
            creation_date = datetime.datetime.utcfromtimestamp(
                attrs["creation_date"]
            ).strftime("%Y-%m-%d")

        return {
            "ok":           True,
            "domain":       registrable,
            "reputation":   attrs.get("reputation", 0),
            "categories":   ", ".join(attrs.get("categories", {}).values()),
            "malicious":    attrs.get("last_analysis_stats", {}).get("malicious",  0),
            "harmless":     attrs.get("last_analysis_stats", {}).get("harmless",   0),
            "suspicious":   attrs.get("last_analysis_stats", {}).get("suspicious", 0),
            "creationDate": creation_date,
            "registrar":    attrs.get("registrar", ""),
            "country":      attrs.get("country",   ""),
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


# ===== URLSCAN.IO — Proxy endpoint =====

@app.post("/api/urlscan")
async def urlscan_search(req: DomainRequest):
    """
    Tìm kiếm kết quả URLScan.io cho domain.
    """
    try:
        registrable = ".".join(req.domain.split(".")[-2:])
        headers = {}
        if URLSCAN_KEY:
            headers["API-Key"] = URLSCAN_KEY

        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{registrable}&size=3&sort=date",
                headers=headers,
            )
            r.raise_for_status()
            data = r.json()

        if not data.get("results"):
            return {"ok": False, "error": "Không có kết quả"}

        latest = data["results"][0]
        verdicts = latest.get("verdicts", {}).get("overall", {})
        return {
            "ok":          True,
            "domain":      registrable,
            "lastScanned": latest.get("task", {}).get("time"),
            "score":       verdicts.get("score",     0),
            "malicious":   verdicts.get("malicious", False),
            "tags":        verdicts.get("tags",      []),
            "screenshot":  latest.get("screenshot"),
            "reportURL":   f"https://urlscan.io/result/{latest.get('task', {}).get('uuid', '')}/",
            "country":     latest.get("page", {}).get("country", ""),
            "server":      latest.get("page", {}).get("server",  ""),
            "ip":          latest.get("page", {}).get("ip",      ""),
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/urlscan-submit")
async def urlscan_submit(req: URLRequest):
    """
    Submit URL mới lên URLScan.io để quét.
    """
    if not URLSCAN_KEY:
        return {"ok": False, "error": "URLSCAN_API_KEY chưa được cấu hình"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            submit = await client.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": URLSCAN_KEY, "Content-Type": "application/json"},
                json={"url": req.url, "visibility": "public"},
            )
            submit.raise_for_status()
            uuid = submit.json().get("uuid")
            if not uuid:
                return {"ok": False, "error": "Không nhận được UUID từ URLScan"}

        await asyncio.sleep(20)

        async with httpx.AsyncClient(timeout=15) as client:
            result = await client.get(
                f"https://urlscan.io/api/v1/result/{uuid}/",
                headers={"API-Key": URLSCAN_KEY},
            )
            result.raise_for_status()
            data = result.json()

        verdicts = data.get("verdicts", {}).get("overall", {})
        return {
            "ok":        True,
            "uuid":      uuid,
            "reportURL": f"https://urlscan.io/result/{uuid}/",
            "screenshot": data.get("task", {}).get("screenshotURL"),
            "malicious": verdicts.get("malicious", False),
            "score":     verdicts.get("score",     0),
            "tags":      verdicts.get("tags",      []),
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


# ===== IPINFO — Proxy endpoint =====

@app.post("/api/ipinfo")
async def ipinfo(req: DomainRequest):
    """
    Lấy thông tin IP/Geo cho domain.
    Backend resolve DNS rồi gọi IPInfo.
    """
    try:
        import socket
        try:
            ip = socket.gethostbyname(req.domain)
        except Exception:
            return {"ok": False, "error": "Không resolve được IP"}

        url = f"https://ipinfo.io/{ip}/json"
        if IPINFO_TOK:
            url += f"?token={IPINFO_TOK}"

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()

        privacy = data.get("privacy", {})
        return {
            "ok":       True,
            "ip":       ip,
            "hostname": data.get("hostname", req.domain),
            "city":     data.get("city",     ""),
            "region":   data.get("region",   ""),
            "country":  data.get("country",  ""),
            "org":      data.get("org",      ""),
            "timezone": data.get("timezone", ""),
            "isVPN":    privacy.get("vpn",   False),
            "isProxy":  privacy.get("proxy", False),
            "isTor":    privacy.get("tor",   False),
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


# ===== FETCH SOURCE — Proxy endpoint =====

@app.post("/api/fetch-source")
async def fetch_source(req: URLRequest):
    """
    Fetch HTML source của URL (server-side, không bị CORS).
    """
    result = await fetch_html(req.url)
    return result


# ===== COMBINED URL SCAN =====

@app.post("/api/url-scan")
async def url_scan_combined(req: URLRequest):
    """
    Endpoint tổng hợp: DNS + VirusTotal + URLScan + IPInfo song song.
    Frontend gọi một endpoint này thay vì gọi từng API riêng.
    """
    url = req.url
    try:
        url_obj = urlparse(url)
        domain  = url_obj.netloc
        is_https = url_obj.scheme == "https"
    except Exception:
        return {"ok": False, "error": "URL không hợp lệ"}

    # Chạy song song tất cả
    vt_task      = asyncio.create_task(_run_vt_scan(url))
    vt_dom_task  = asyncio.create_task(_run_vt_domain(domain))
    urlscan_task = asyncio.create_task(_run_urlscan(domain))
    ipinfo_task  = asyncio.create_task(_run_ipinfo(domain))

    vt, vt_domain_data, urlscan_data, geo = await asyncio.gather(
        vt_task, vt_dom_task, urlscan_task, ipinfo_task,
        return_exceptions=True
    )

    def safe(val):
        return None if isinstance(val, Exception) else val

    vt              = safe(vt)
    vt_domain_data  = safe(vt_domain_data)
    urlscan_data    = safe(urlscan_data)
    geo             = safe(geo)

    # Tính threat score
    threat_score = 0
    if not is_https:                          threat_score += 25
    if vt  and vt.get("malicious",  0) > 0:  threat_score += min(vt["malicious"]  * 8, 40)
    if vt  and vt.get("suspicious", 0) > 0:  threat_score += min(vt["suspicious"] * 4, 20)
    if urlscan_data and urlscan_data.get("malicious"): threat_score += 30
    if geo and geo.get("isTor"):              threat_score += 25
    if geo and geo.get("isVPN"):              threat_score += 10
    threat_score = min(100, threat_score)

    return {
        "ok":         True,
        "url":        url,
        "domain":     domain,
        "isHTTPS":    is_https,
        "vt":         vt,
        "vtDomain":   vt_domain_data,
        "urlscan":    urlscan_data,
        "geo":        geo,
        "threatScore": threat_score,
    }


# ===== ORIGINAL ANALYZE URL (giữ tương thích) =====

@app.post("/api/analyze/url")
async def analyze_url(req: URLRequest):
    url = req.url
    fetch_result = await fetch_html(url)
    if not fetch_result["success"]:
        return {"success": False, "stage": "fetch", "error": fetch_result["error"]}

    ai_result = await analyze_text(fetch_result["html"])
    if not ai_result["success"]:
        return {"success": False, "stage": "ai", "error": ai_result["error"]}

    return {
        "success":     True,
        "url":         url,
        "domain":      extract_domain(url),
        "status":      fetch_result["status"],
        "ai_analysis": ai_result["data"],
    }


# ===== INTERNAL HELPERS =====

async def _run_vt_scan(url: str):
    if not VT_KEY:
        return None
    try:
        req = URLRequest(url=url)
        result = await vt_scan(req)
        return result if result.get("ok") else None
    except Exception:
        return None

async def _run_vt_domain(domain: str):
    if not VT_KEY:
        return None
    try:
        req = DomainRequest(domain=domain)
        result = await vt_domain(req)
        return result if result.get("ok") else None
    except Exception:
        return None

async def _run_urlscan(domain: str):
    try:
        req = DomainRequest(domain=domain)
        result = await urlscan_search(req)
        return result if result.get("ok") else None
    except Exception:
        return None

async def _run_ipinfo(domain: str):
    try:
        req = DomainRequest(domain=domain)
        result = await ipinfo(req)
        return result if result.get("ok") else None
    except Exception:
        return None
