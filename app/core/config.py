import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set")

if not JWT_SECRET:
    raise ValueError("JWT_SECRET is not set")