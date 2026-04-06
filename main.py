from fastapi import FastAPI
from pydantic import BaseModel
import httpx
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# ===== CONFIG =====
TEXT_API = "https://text-service-glgj.onrender.com/detect"

# ===== CORS (QUAN TRỌNG) =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # production nên thay bằng domain frontend
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== MODEL =====
class URLRequest(BaseModel):
    url: str


# ===== UTILS =====
async def fetch_html(url: str):
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html",
    }

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(url, headers=headers)

            return {
                "success": True,
                "html": r.text[:5000],
                "status": r.status_code
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Timeout khi fetch URL",
            "status": 408
        }

    except httpx.RequestError:
        return {
            "success": False,
            "error": "Không thể kết nối tới URL",
            "status": 500
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "status": 500
        }


async def analyze_text(content: str):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(TEXT_API, json={
                "content": content
            })

            if r.status_code != 200:
                return {
                    "success": False,
                    "error": "AI service lỗi",
                }

            try:
                return {
                    "success": True,
                    "data": r.json()
                }
            except:
                return {
                    "success": False,
                    "error": "AI trả về dữ liệu không hợp lệ"
                }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "AI timeout"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def extract_domain(url: str):
    return urlparse(url).netloc


# ===== MAIN API =====
@app.post("/api/analyze/url")
async def analyze_url(req: URLRequest):
    url = req.url

    # 1. fetch HTML
    fetch_result = await fetch_html(url)

    if not fetch_result["success"]:
        return {
            "success": False,
            "stage": "fetch",
            "error": fetch_result["error"]
        }

    html = fetch_result["html"]
    status = fetch_result["status"]

    # 2. AI analyze
    ai_result = await analyze_text(html)

    if not ai_result["success"]:
        return {
            "success": False,
            "stage": "ai",
            "error": ai_result["error"]
        }

    # 3. success
    return {
        "success": True,
        "url": url,
        "domain": extract_domain(url),
        "status": status,
        "ai_analysis": ai_result["data"]
    }


# ===== HEALTH =====
@app.get("/health")
def health():
    return {"status": "ok"}
