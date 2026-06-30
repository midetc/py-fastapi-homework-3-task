from typing import Literal

from pydantic import BaseModel, EmailStr, field_validator

from database.validators.accounts import validate_password_strength, validate_email
from security import interfaces


class UserRegistrationBaseSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, value: str) -> str:
        email = validate_email(value)
        return email


class UserRegistrationRequestSchema(UserRegistrationBaseSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_user_password_strength(cls, value: str) -> str:
        validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(UserRegistrationBaseSchema):
    id: int


class UserActivationRequestSchema(UserRegistrationBaseSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserRegistrationBaseSchema):
    pass


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    token: str


class UserLoginRequestSchema(UserRegistrationBaseSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"]


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
