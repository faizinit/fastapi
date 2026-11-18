from fastapi import APIRouter

from app.api.deps import (
    AuditDep,
    DatabaseDep,
    GatewayDep,
    MetaDep,
    MetricsDep,
    PrincipalDep,
    RateLimiterDep,
    RecorderDep,
    SettingsDep,
)
from app.core.exceptions import error_responses
from app.schemas.llm import LLMProcessRequest, LLMProcessResponse
from app.services.llm_processing import LLMProcessingService

router = APIRouter(prefix="/llm", tags=["llm"])


@router.post(
    "/process",
    response_model=LLMProcessResponse,
    status_code=200,
    summary="Process a request through the security gateway",
    description=(
        "The only way business applications reach an LLM. The caller is authenticated from its "
        "token, authorized for the project, task and model, and the request is validated against "
        "policy before the provider is called; the response is validated and an audit record is "
        "written before the result is returned. `requestId` must be unique per project."
    ),
    responses=error_responses(400, 401, 403, 409, 413, 429, 502, 503, 504),
)
async def process_llm_request(
    body: LLMProcessRequest,
    principal: PrincipalDep,
    meta: MetaDep,
    database: DatabaseDep,
    settings: SettingsDep,
    recorder: RecorderDep,
    limiter: RateLimiterDep,
    gateway: GatewayDep,
    audit: AuditDep,
    metrics: MetricsDep,
) -> LLMProcessResponse:
    service = LLMProcessingService(
        database=database,
        settings=settings,
        recorder=recorder,
        limiter=limiter,
        gateway=gateway,
        audit=audit,
        metrics=metrics,
    )
    return await service.process(principal, body, meta)
