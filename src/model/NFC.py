from typing import Optional
from pydantic import BaseModel

class ReadCardRequest(BaseModel):
    blockNumber: list[int]
    
class WriteCardRequest(BaseModel):
    blockNumber: int
    data: str
    
class WriteCardUserRequest(BaseModel):
    username: str
    role_id: str
    institution_id: str
    
class UserCheckInOutRequest(BaseModel):
    username: str
    source_in: str
    source_out: str