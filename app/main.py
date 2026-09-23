from fastapi import FastAPI
from app.database import db

app = FastAPI(
    title="Employee Task Management API",
    version="1.0.0"
)

@app.on_event("startup")
async def startup():
    await db.connect()

@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()
    
@app.get("/")
async def root():
    return {
        "status": True,
        "message": "Employee Task Management API is running"
    }