import re
from decimal import Decimal, InvalidOperation
from typing import Literal, Optional
from urllib.parse import urlsplit

from pydantic import AliasChoices, BaseModel, Field, ValidationInfo, field_validator


class RegisterIn(BaseModel):
    full_name: str = Field(min_length=1, max_length=100, pattern=r".*\S.*")
    email: str = Field(
        min_length=3,
        max_length=255,
        pattern=r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$",
    )
    master_password: str = Field(min_length=12, max_length=128)
    confirm_password: str = Field(min_length=12, max_length=128)


class LoginIn(BaseModel):
    email: str = Field(
        min_length=3,
        max_length=255,
        pattern=r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$",
    )
    master_password: str = Field(min_length=1, max_length=128)


class LoginVerifyIn(BaseModel):
    challenge_id: str = Field(min_length=40, max_length=128)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class LoginResendIn(BaseModel):
    challenge_id: str = Field(min_length=40, max_length=128)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class EntryFieldIn(BaseModel):
    label: str = Field(min_length=1, max_length=100, pattern=r".*\S.*")
    type: Literal["text", "password", "email", "url", "number", "multiline"] = "text"
    value: str = Field(default="", max_length=10000)
    sensitive: bool = False

    @field_validator("value")
    @classmethod
    def validate_value_for_type(cls, value: str, info: ValidationInfo) -> str:
        if not value:
            return value

        field_type = info.data.get("type", "text")
        if field_type == "email" and not re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+",
            value,
        ):
            raise ValueError("Enter a valid email address")
        if field_type == "url":
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Enter a valid HTTP or HTTPS URL")
        if field_type == "number":
            try:
                number = Decimal(value)
            except InvalidOperation as exc:
                raise ValueError("Enter a valid number") from exc
            if not number.is_finite():
                raise ValueError("Enter a finite number")
        return value


class EntryIn(BaseModel):
    title: str = Field(
        min_length=1,
        max_length=255,
        pattern=r".*\S.*",
        validation_alias=AliasChoices("title", "site_name"),
    )
    site_url: Optional[str] = Field(default=None, max_length=500)
    username: str = Field(default="", max_length=250)
    password: str = Field(default="", max_length=500)
    category: str = Field(default="Other", max_length=100)
    notes: Optional[str] = Field(default=None, max_length=1000)
    favourite: bool = False
    fields: Optional[list[EntryFieldIn]] = None


class PasswordIn(BaseModel):
    password: str = Field(min_length=1, max_length=500)


class EntryEditAuthIn(BaseModel):
    master_password: str = Field(min_length=1, max_length=128)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=12, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)
    confirm_password: str = Field(min_length=12, max_length=128)
