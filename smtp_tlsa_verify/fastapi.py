import os
from typing import Union

from fastapi import FastAPI
import pydantic

from smtp_tlsa_verify.verification import verify, VerificationResult

app = FastAPI()

OPENSSL_PATH = os.environ.get('OPENSSLPATH', None)


@app.get("/")
def read_root():
    return {"Hello": "World"}


class VerificationRequest(pydantic.BaseModel):
    hostname: str


@app.post("/verification/")
def verify_hostname(verification_req: VerificationRequest) -> VerificationResult:
    result = verify(verification_req.hostname, openssl=OPENSSL_PATH)
    return result