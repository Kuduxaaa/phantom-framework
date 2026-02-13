from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application configuration settings.
    """

    PROJECT_NAME: str = 'Phanthom'
    VERSION: str = '0.1.0'
    API_V1_PREFIX: str = '/api/v1'
    DEBUG: bool = False
    
    DATABASE_URL: str
    SECRET_KEY: str
    
    class Config:
        env_file = '.env'
        case_sensitive = True


settings = Settings()
