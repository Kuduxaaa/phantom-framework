from abc import ABC
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from typing import Generic, TypeVar, Type, Optional, List

ModelType = TypeVar('ModelType')


class BaseRepository(ABC, Generic[ModelType]):
    """
    Generic repository pattern for database operations.
    """

    def __init__(self, model: Type[ModelType], db: AsyncSession):
        self.model = model
        self.db = db
    
    async def get(self, id: int) -> Optional[ModelType]:
        """
        Get single record by ID.
        
        Args:
            id: Record ID
            
        Returns:
            Model instance or None
        """

        result = await self.db.execute(
            select(self.model).where(self.model.id == id)
        )
        
        return result.scalar_one_or_none()
    
    async def list(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        """
        List records with pagination.
        
        Args:
            skip: Records to skip
            limit: Max records to return
            
        Returns:
            List of model instances
        """

        result = await self.db.execute(
            select(self.model).offset(skip).limit(limit)
        )
        
        return list(result.scalars().all())
    
    async def create(self, obj_in: dict) -> ModelType:
        """
        Create new record.
        
        Args:
            obj_in: Data dictionary
            
        Returns:
            Created model instance
        """

        db_obj = self.model(**obj_in)
        
        self.db.add(db_obj)
        await self.db.commit()
        await self.db.refresh(db_obj)
        
        return db_obj
    
    async def update(self, id: int, obj_in: dict) -> Optional[ModelType]:
        """
        Update existing record.
        
        Args:
            id: Record ID
            obj_in: Update data
            
        Returns:
            Updated model instance or None
        """

        db_obj = await self.get(id)
        
        if not db_obj:
            return None
        
        for field, value in obj_in.items():
            setattr(db_obj, field, value)
        
        await self.db.commit()
        await self.db.refresh(db_obj)
        
        return db_obj
    
    async def delete(self, id: int) -> bool:
        """
        Delete record.
        
        Args:
            id: Record ID
            
        Returns:
            True if deleted, False if not found
        """

        db_obj = await self.get(id)
        
        if not db_obj:
            return False
        
        await self.db.delete(db_obj)
        await self.db.commit()
        
        return True
