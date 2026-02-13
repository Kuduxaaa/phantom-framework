from fastapi import HTTPException, status


class AppException(Exception):
    """
    Base application exception.
    """

    pass


class NotFoundException(AppException):
    """
    Resource not found exception.
    """

    pass


class ValidationException(AppException):
    """
    Validation error exception.
    """

    pass


class ModuleException(AppException):
    """
    Module execution exception.
    """

    pass


def not_found(resource: str, id: int) -> HTTPException:
    """
    Generate 404 HTTPException.
    
    Args:
        resource: Resource type
        id: Resource ID
        
    Returns:
        HTTPException with 404 status
    """

    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f'{resource} with id {id} not found'
    )


def validation_error(detail: str) -> HTTPException:
    """
    Generate 422 HTTPException.
    
    Args:
        detail: Error detail message
        
    Returns:
        HTTPException with 422 status
    """

    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=detail
    )
