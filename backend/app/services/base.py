from abc import ABC

from app.repositories.base import BaseRepository

from typing import Generic, TypeVar

RepositoryType = TypeVar('RepositoryType', bound=BaseRepository)


class BaseService(ABC, Generic[RepositoryType]):
    """
    Base service class for business logic.
    """

    def __init__(self, repository: RepositoryType):
        self.repository = repository
