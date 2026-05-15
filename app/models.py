from sqlmodel import SQLModel, Field
from typing import Optional


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    full_name: str
    username: str = Field(index=True, unique=True)
    hashed_password: str


class UserCreate(SQLModel):
    full_name: str
    username: str
    password: str


class UserResponse(SQLModel):
    id: int
    full_name: str
    username: str
    hashed_password: str