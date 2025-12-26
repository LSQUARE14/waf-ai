import os

class Config:
    SECRET_KEY = os.getenv("GROQ_API_KEY", "default-secret-key")
