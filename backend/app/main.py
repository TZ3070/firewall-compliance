from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.dependencies import get_knowledge_store
from app.api.router import api_router
from app.core.config import get_settings


@asynccontextmanager
async def lifespan(_application: FastAPI):
    yield
    if get_knowledge_store.cache_info().currsize:
        get_knowledge_store().close()
        get_knowledge_store.cache_clear()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )
    application.include_router(api_router)
    return application


app = create_app()
