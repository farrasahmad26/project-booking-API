from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import hash_password, create_access_token, verify_password
from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse, UserLogin


router = APIRouter(
    prefix='/auth',
    tags=['Auth']
)


@router.post(
    '/register',
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
def register(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    existing_user = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='Email already registered'
        )
    
    new_user = User(
        name=user_data.name,
        email=user_data.email,
        password_hash=hash_password(user_data.password),
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user

@router.post('/login')
def login(
    user_data: UserLogin,
    db: Session = Depends(get_db)
):
    user = (
        db.query(User).filter(User.email == user_data.email).first()
    )

    if not user or not verify_password(
        user_data.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid email or password'
        )
    
    access_token = create_access_token(user.id)

    return {
        'access_token': access_token,
        'token_type': 'bearer'
    }