from datetime import datetime, timedelta

import jwt

from typing import Optional

from dynaconf import Dynaconf
from fastapi import FastAPI, Response, Depends, Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.hash import argon2
from pydantic import BaseModel
from pymongo import MongoClient

config = Dynaconf(settings_files=["settings.yml"])

mongo_uri = f"mongodb://{config.mongo.username}:{config.mongo.password}@{config.mongo.hostname}"
print(mongo_uri)


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str) -> bool:
        is_token_valid = False

        try:
            # validates the jwt token
            payload = jwt.decode(jwtoken, config.secret_key, algorithms=["HS256"])
        except:
            payload = None
        if payload:
            is_token_valid = True
        return is_token_valid


api = FastAPI(title="fast_api_playground")
mongo = MongoClient(mongo_uri)
db = mongo.get_database("test")
colle = db.get_collection("test_users")


class User(BaseModel):
    name: str
    surname: Optional[str] = None
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    uid: str


@api.post("/user/create", response_model=UserResponse)
async def create_user(user: User):
    user.password = argon2.hash(user.password)
    uid = colle.insert_one(user.dict()).inserted_id
    return UserResponse(uid=str(uid))


@api.post("/user/login")
async def try_login(credentials: UserLogin, response: Response):
    user = colle.find_one({"email": credentials.email})
    if not user:
        response.status_code = 403
        return {}
    if argon2.verify(credentials.password, user.get("password")):
        return jwt.encode({
            "sub": user.get("email"),
            "exp": datetime.utcnow() + timedelta(seconds=1800),
            "nbf": datetime.utcnow() + timedelta(seconds=60),
            "name": user.get("name"),
        }, config.secret_key, algorithm="HS256")
    else:
        response.status_code = 403
        return {}


@api.put("/user/update", dependencies=[Depends(JWTBearer())])
async def update_user(user: User):
    return {}
