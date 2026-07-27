import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = "your_secret_key"
    FLASK_ENV = "development"
    MONGO_URI = "mongodb://mongo:27017/MY_DB"
    AZURE_CONTAINER_NAME = "documents"

    # JWT auth config
    # IMPORTANT: override JWT_SECRET_KEY via an environment variable in production
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    JWT_EXP_HOURS = int(os.environ.get("JWT_EXP_HOURS", 12))
    
    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'dinesh.ravi.kumar115@gmail.com'
    MAIL_PASSWORD = 'ogvi pzkl oxld eyib'
    MAIL_DEFAULT_SENDER = 'dinesh.ravi.kumar115@gmail.com'
    
    # API Keys (Note: Consider moving these to environment variables)
    AZURE_CONNECTION_STRING = os.environ.get("AZURE_CONNECTION_STRING")