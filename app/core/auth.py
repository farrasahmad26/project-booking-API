from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import settings
from app.db.dependencies import get_db
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')

