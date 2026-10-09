from fastapi import FastAPI
from app.database import db
from app.routers.users import router as users_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Employee Task Management API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await db.connect()

@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()

app.include_router(users_router)

@app.get("/")
async def root():
    return {
        "status": True,
        "message": "Employee Task Management API is running"
    }