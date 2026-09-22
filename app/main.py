from fastapi import FastAPI

app = FastAPI(
    title="Employee Task Management API",
    version="1.0.0"
)

@app.get("/")
async def root():
    return {
        "status": True,
        "message": "Employee Task Management API is running"
    }