from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas.accounts import UserRegistrationResponseSchema, UserRegistrationRequestSchema, MessageResponseSchema, \
    UserActivationRequestSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshRequestSchema, TokenRefreshResponseSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.utils import generate_secure_token

router = APIRouter()


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    try:
        hashed = hash_password(user.password)
        group_stmt = select(UserGroupModel).where(UserGroupModel.name == "user")
        group_result = await db.execute(group_stmt)
        group = group_result.scalars().first()
        if not group:
            group = UserGroupModel(name="user")
            db.add(group)
            await db.flush()
        db_user = UserModel(
            email=user.email,
            _hashed_password=hashed,
            is_active=False,
            group_id=group.id,
        )
        activation_token = ActivationTokenModel(user=db_user)
        db.add(db_user)
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)
        await db.refresh(activation_token)
        return db_user
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")
    return await create_user(db, user)


@router.post("/activate/", response_model=MessageResponseSchema, status_code=200)
async def activate(user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(status_code=400, detail=f"A user with this email {user.email} not found.")
    activating_token_stmt = select(ActivationTokenModel).where(ActivationTokenModel.user_id == db_user.id)
    activating_token_result = await db.execute(activating_token_stmt)
    activating_token = activating_token_result.scalars().first()
    if not activating_token or activating_token.expires_at < datetime.now():
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    try:
        db_user.is_active = True
        await db.delete(activating_token)
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=200)
async def password_reset_request(user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user and db_user.is_active:
        try:
            password_reset_token_stmt = select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == db_user.id
            )
            password_reset_token_result = await db.execute(password_reset_token_stmt)
            password_reset_tokens = password_reset_token_result.scalars().all()
            if password_reset_tokens:
                await db.delete(password_reset_tokens)
                await db.commit()

            password_reset_token = PasswordResetTokenModel(user=db_user)
            db.add(password_reset_token)
            await db.commit()
            await db.refresh(db_user)
            await db.refresh(password_reset_token)
        except SQLAlchemyError:
            return {"message": "If you are registered, you will receive an email with instructions."}
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=200)
async def reset_password_complete(user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        password_reset_token_stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
        password_reset_token_result = await db.execute(password_reset_token_stmt)
        password_reset_token = password_reset_token_result.scalars().first()
        if password_reset_token.token != user.token or password_reset_token.expires_at < datetime.now():
            await db.delete(password_reset_token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        db_user.password = user.password
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
        user: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    db_user = await get_user_by_email(db, user.email)
    if not db_user or not db_user.verify_password(user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")
    try:
        access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})
        refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_manager.create_refresh_token(data={"user_id": db_user.id}),
        )
        db.add(refresh_token)
        await db.commit()
        await db.refresh(refresh_token)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token.token,
            "token_type": "bearer",
        }
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
async def acc_refresh(
        refresh_token: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(refresh_token.refresh_token)
    except BaseSecurityError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    token_result = await db.execute(select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh_token.refresh_token
    ))
    if not token_result.scalar_one_or_none():
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    user_result = await db.execute(select(UserModel).where(UserModel.id == decoded_token.get("user_id")))
    if not user_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="User not found.")
    access_token = jwt_manager.create_access_token(data={"user_id": decoded_token.get("user_id")})
    return {"access_token": access_token}
