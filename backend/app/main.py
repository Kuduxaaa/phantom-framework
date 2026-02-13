from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.api.v1 import api_router
from app.utils.logger import logger

app = FastAPI(
    title   = settings.PROJECT_NAME,
    version = settings.VERSION,
    debug   = settings.DEBUG
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.on_event('startup')
async def startup_event():
    """
    Application startup event.
    """

    logger.info(f'Starting {settings.PROJECT_NAME} v{settings.VERSION}')


@app.on_event('shutdown')
async def shutdown_event():
    """
    Application shutdown event.
    """

    logger.info('Shutting down application')


@app.get('/')
async def root():
    """
    Root endpoint.
    
    Returns:
        API information
    """

    return {
        'success': True, 
        'system': { 
            'name': 'Phantom Framework', 
            'status': 'online',
            'websocket': 'available'
        }, 
        'message': 'Ni Dieu ni maître ❤️' 
    }
