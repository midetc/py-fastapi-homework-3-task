from datetime import datetime, timezone
from typing import Annotated
from http import HTTPStatus
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager
from database import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from database import get_db
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema
from schemas.accounts import (
    UserActivationRequestSchema,
    MessageResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
)
from security.passwords import hash_password, verify_password
from security.token_manager import JWTAuthManager

router = APIRouter()
DbSession = Annotated[AsyncSession, Depends(get_db)]
AuthManager = Annotated[JWTAuthManager, Depends(get_jwt_auth_manager)]


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=HTTPStatus.CREATED,
)
async def create_user(user_data: UserRegistrationRequestSchema, db: DbSession):
    group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db.execute(group_stmt)
    group_db = result.scalar_one_or_none()
    if not group_db:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Default user group not found"
        )

    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(stmt)
    user_db = result.scalar_one_or_none()

    if user_db:
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    user = UserModel.create(
        email=user_data.email, raw_password=user_data.password, group_id=group_db.id
    )

    user.activation_token = ActivationTokenModel()

    try:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    return user


@router.post(
    "/activate/", response_model=MessageResponseSchema, status_code=HTTPStatus.OK
)
async def activate_user(activation_data: UserActivationRequestSchema, db: DbSession):
    stmt = (
        select(UserModel)
        .where(UserModel.email == activation_data.email)
        .options(joinedload(UserModel.activation_token))
    )

    result = await db.execute(stmt)
    user_db = result.scalar_one_or_none()
    if not user_db:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Invalid or expired activation token."
        )

    if user_db.is_active:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="User account is already active."
        )

    if not user_db.activation_token:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user_db.activation_token.token != activation_data.token:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Invalid or expired activation token."
        )

    if (
        datetime.now(timezone.utc).replace(tzinfo=None)
        >= user_db.activation_token.expires_at
    ):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user_db.is_active = True
    user_db.activation_token = None

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    return {"message": "User account activated successfully."}


@router.post(
    "/login/", response_model=UserLoginResponseSchema, status_code=HTTPStatus.CREATED
)
async def login_user(
    login_data: UserLoginRequestSchema, db: DbSession, auth_manager: AuthManager
):
    stmt = (
        select(UserModel)
        .where(UserModel.email == login_data.email)
        .options(joinedload(UserModel.refresh_tokens))
    )
    result = await db.execute(stmt)
    user = result.unique().scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail="User account is not activated."
        )

    result_verify_password = user.verify_password(login_data.password)
    if not result_verify_password:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid email or password."
        )

    user_payload = {"user_id": int(user.id)}
    access_token = auth_manager.create_access_token(user_payload)
    refresh_token = auth_manager.create_refresh_token(user_payload)
    new_refresh_token = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=7,
        token=refresh_token,
    )
    user.refresh_tokens.append(new_refresh_token)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/refresh/", response_model=TokenRefreshResponseSchema, status_code=HTTPStatus.OK
)
async def refresh_token(
    data: TokenRefreshRequestSchema, db: DbSession, auth_manager: AuthManager
):
    try:

        payload = auth_manager.decode_refresh_token(data.refresh_token)
        user_id_raw = payload.get("user_id")
        if user_id_raw is None:
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid token payload."
            )

        user_id = int(user_id_raw)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Token has expired."
        )

    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.user_id == user_id,
        RefreshTokenModel.token == data.refresh_token,
    )
    result = await db.execute(stmt)
    existing_token = result.scalar_one_or_none()
    if not existing_token:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Refresh token not found."
        )

    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()
    if not existing_user:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="User not found.")
    new_access_token = auth_manager.create_access_token(payload)
    return {"access_token": new_access_token}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=HTTPStatus.OK,
)
async def reset_password(
    data: PasswordResetRequestSchema,
    db: DbSession,
):
    message = {
        "message": "If you are registered, "
        "you will receive an email with instructions."
    }
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    exisitng_user = result.scalar_one_or_none()
    if not exisitng_user or not exisitng_user.is_active:
        return message

    stmt = delete(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == exisitng_user.id
    )
    new_password_token = PasswordResetTokenModel(user_id=exisitng_user.id)
    try:
        await db.execute(stmt)
        db.add(new_password_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )
    return message


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=HTTPStatus.OK,
)
async def reset_password_complete(
    data: PasswordResetCompleteRequestSchema,
    db: DbSession,
):
    stmt = (
        select(PasswordResetTokenModel)
        .join(PasswordResetTokenModel.user)
        .where(UserModel.email == data.email)
        .options(joinedload(PasswordResetTokenModel.user))
    )
    result = await db.execute(stmt)
    existing_token = result.scalar_one_or_none()

    if existing_token and existing_token.token != data.token:
        await db.delete(existing_token)
        await db.commit()
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Invalid email or token."
        )

    if not existing_token:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Invalid email or token."
        )

    if datetime.now(timezone.utc).replace(tzinfo=None) >= existing_token.expires_at:
        await db.delete(existing_token)
        await db.commit()
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Invalid email or token."
        )

    user = existing_token.user

    if not user or not user.is_active:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Invalid email or token."
        )

    user.password = data.password

    try:
        await db.delete(existing_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}
