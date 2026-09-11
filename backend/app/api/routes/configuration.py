from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.errors import ConfigurationPipelineError
from app.models.contracts import CurrentConfigResponse
from app.services.configuration import ConfigurationService


router = APIRouter(prefix="/api/v1/config", tags=["configuration"])


@lru_cache
def get_configuration_service() -> ConfigurationService:
    return ConfigurationService()


@router.get("/current", response_model=CurrentConfigResponse)
async def get_current_config(
    service: Annotated[ConfigurationService, Depends(get_configuration_service)],
) -> CurrentConfigResponse:
    try:
        return await service.get_current_config()
    except ConfigurationPipelineError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
