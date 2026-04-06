from fastapi import FastAPI, Query
from pydantic import BaseModel
import httpx
from urllib.parse import urlparse

app = FastAPI()

# ===== CONFIG =====
TEXT_API = "https://text-service-glgj.onrender.com/detect"

# ===== MODEL =====
class URLRequest(BaseModel):
    url: str


# ===== UTILS =====
async def fetch_html(url: str):
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html",
    }

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url, headers=headers)
        return r.text[:5000], r.status_code


async def analyze_text(content: str):
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(TEXT_API, json={
            "content": content
        })
        return r.json()


def extract_domain(url: str):
    return urlparse(url).netloc


# ===== MAIN API =====
@app.post("/api/analyze/url")
async def analyze_url(req: URLRequest):
    url = req.url

    try:
        html, status = await fetch_html(url)

        ai_result = await analyze_text(html)

        return {
            "url": url,
            "status": status,
            "domain": extract_domain(url),
            "ai_analysis": ai_result
        }

    except Exception as e:
        return {
            "error": str(e)
        }


# ===== HEALTH =====
@app.get("/health")
def health():
    return {"status": "ok"}
