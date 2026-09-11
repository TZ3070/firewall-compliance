from fastapi import APIRouter

from app.api.routes.configuration import router as configuration_router
from app.api.routes.health import router as health_router
from app.api.routes.agent_tools import router as agent_tools_router
from app.api.routes.assessments import router as assessments_router
from app.api.routes.conversation_agent import router as conversation_agent_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(configuration_router)
api_router.include_router(agent_tools_router)
api_router.include_router(assessments_router)
api_router.include_router(conversation_agent_router)
