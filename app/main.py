import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.db import init_db
from app.middleware import BlockerMiddleware
from app.portal import router as portal_router
from app.admin import router as admin_router
from app.watcher import watcher
from app.sweeper import sweeper

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    watcher_task = asyncio.create_task(watcher.run())
    sweeper_task = asyncio.create_task(sweeper.run())
    yield
    # Shutdown
    watcher.stop()
    sweeper.stop()
    watcher_task.cancel()
    sweeper_task.cancel()
    try:
        await asyncio.gather(watcher_task, sweeper_task, return_exceptions=True)
    except Exception:
        pass

def create_app() -> FastAPI:
    app = FastAPI(title="Sentinel Intrusion Detection", lifespan=lifespan)
    
    # Mount Blocker Middleware
    app.add_middleware(BlockerMiddleware)

    # Mount Public Health Endpoint
    @app.get("/health")
    def health():
        return {"status": "ok", "service": "sentinel"}

    # Mount Portal & Admin routers
    app.include_router(portal_router)
    app.include_router(admin_router)

    return app

app = create_app()
