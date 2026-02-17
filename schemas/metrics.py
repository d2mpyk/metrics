"""Relacionado a los Schemas en la APP"""
from pydantic import BaseModel


class EncryptedMetrics(BaseModel):
    nonce: str
    ciphertext: str