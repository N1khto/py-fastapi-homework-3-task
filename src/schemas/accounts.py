from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators, UserGroupEnum


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)


class UserRegistrationRequestSchema(UserBase):
    password: str

    model_config = {
        "from_attributes": True,
    }

    @field_validator("password", mode="before")
    @classmethod
    def normalize_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = {
        "from_attributes": True,
    }


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserBase):
    token: str
    password: str

    @field_validator("password", mode="before")
    @classmethod
    def normalize_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(UserBase):
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
