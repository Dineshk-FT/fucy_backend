class Config:
    SECRET_KEY = "your_secret_key"
    FLASK_ENV = "development"
    MONGO_URI = "mongodb://mongo:27017/MY_DB"
    AZURE_CONTAINER_NAME = "documents"
    
    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'dinesh.ravi.kumar115@gmail.com'
    MAIL_PASSWORD = 'ogvi pzkl oxld eyib'
    MAIL_DEFAULT_SENDER = 'dinesh.ravi.kumar115@gmail.com'
    
    # API Keys (Note: Consider moving these to environment variables)

    AZURE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net"