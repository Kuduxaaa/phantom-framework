from fastapi import APIRouter

from app.api.v1 import routes

api_router = APIRouter()

api_router.include_router(routes.router, tags=['general'])
