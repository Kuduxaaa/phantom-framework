from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal

from typing import AsyncGenerator


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting async database sessions.
    
    Yields:
        AsyncSession: Database session
    """

    async with AsyncSessionLocal() as session:
        try:
            yield session

        finally:
            await session.close()
