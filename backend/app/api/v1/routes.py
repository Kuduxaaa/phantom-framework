from fastapi import APIRouter

router = APIRouter()


@router.get('/health')
async def health_check():
    """
    Health check endpoint.
    
    Returns:
        Health status
    """

    return {
        'status': 'healthy',
        'message': 'API is running'
    }


@router.get('/hello')
async def hello_world():
    """
    Hello World endpoint.
    
    Returns:
        Simple greeting message
    """

    return {'message': 'Hello from FastAPI Starter Kit!'}
