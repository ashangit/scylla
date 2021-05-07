import uvicorn
from fastapi import FastAPI

from api.v1.api import api_router
from core.config import API_V1_STR

app = FastAPI(title='RestScylla')
app.include_router(api_router, prefix=API_V1_STR)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
