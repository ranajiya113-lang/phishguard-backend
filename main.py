from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from app.detector import PhishingDetector

app = FastAPI(
    title="Phishing URL Detector API",
    description="High-accuracy phishing URL detection using ML + heuristics + threat intelligence",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = PhishingDetector()

class URLRequest(BaseModel):
    url: str
    virustotal_api_key: str = None  # Optional: user can provide their own key
    google_api_key: str = None       # Optional: user can provide their own key

class URLResponse(BaseModel):
    url: str
    is_phishing: bool
    risk_score: float          # 0.0 (safe) to 1.0 (phishing)
    risk_level: str            # "safe", "suspicious", "dangerous"
    confidence: float          # How confident we are
    details: dict              # Breakdown of detection signals


@app.get("/")
def root():
    return {"message": "Phishing Detector API is running", "version": "1.0.0"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/detect", response_model=URLResponse)
async def detect_url(request: URLRequest):
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    result = await detector.analyze(
        request.url.strip(),
        vt_api_key=request.virustotal_api_key,
        google_api_key=request.google_api_key
    )
    return result


@app.post("/detect/batch")
async def detect_batch(urls: list[str]):
    if len(urls) > 20:
        raise HTTPException(status_code=400, detail="Max 20 URLs per batch request")
    results = []
    for url in urls:
        result = await detector.analyze(url.strip())
        results.append(result)
    return {"results": results}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
