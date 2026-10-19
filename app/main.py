from fastapi import FastAPI
from app.database import db
from app.routers.users import router as users_router
from fastapi.middleware.cors import CORSMiddleware
from app.routers.tasks import router as tasks_router
from app.routers.agency import router as agency_router

app = FastAPI(
    title="Employee Task Management API",
    version="1.0.0",
    # Disable automatic trailing-slash redirects (307).
    # Some HTTP clients (fetch, axios) drop the request body when following
    # a 307 redirect from POST /agencies -> POST /agencies/, causing silent
    # 404 / empty-body errors. We register both paths explicitly instead.
    redirect_slashes=False,
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
app.include_router(tasks_router)
app.include_router(agency_router)

@app.get("/")
async def root():
    return {
        "status": True,
        "message": "Employee Task Management API is running"
    }