from fastapi import APIRouter

from app.api.routes.chat import router as chat_router
from app.api.routes.configuration import router as configuration_router
from app.api.routes.health import router as health_router
from app.api.routes.reports import router as reports_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(configuration_router)
api_router.include_router(reports_router)
api_router.include_router(chat_router)
