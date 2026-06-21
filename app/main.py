"""FastAPI entrypoint — exactly two endpoints: POST /analyze, GET /policy."""
import logging

from fastapi import FastAPI

from app.core.engine import analyze as run_analysis
from app.policy import get_policy
from app.schemas import AnalyzeRequest, AnalyzeResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentraguard")

app = FastAPI(title="SentraGuard Lite", version="1")


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    docs = [doc.model_dump() for doc in request.context_docs]
    result = run_analysis(request.prompt, docs)
    # Safe logging: metadata only, never raw prompt/PII.
    request_id = request.metadata.request_id if request.metadata else "n/a"
    logger.info(
        "analyze request_id=%s decision=%s score=%s tags=%s docs=%s",
        request_id,
        result["decision"],
        result["risk_score"],
        result["risk_tags"],
        len(docs),
    )
    return AnalyzeResponse(**result)


@app.get("/policy")
def policy() -> dict:
    return get_policy()
