from typing import List, Optional

from pydantic import BaseModel


class PostAuth(BaseModel):
    password: str


class ResponseAuth(BaseModel):
    username: str
    groups: Optional[List[str]]
