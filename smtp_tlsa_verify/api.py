import os
from typing import Union

from fastapi import FastAPI, Request
import pydantic

from smtp_tlsa_verify.verification import verify, VerificationResult

app = FastAPI()


OPENSSL_PATH = os.environ.get('OPENSSLPATH', None)


@app.get("/")
def welcome_message(request: Request):
    return {"message": f"Welcome to the SMTP TLSA Resource Record verification service. Please see docs: {request.url}docs/"}


class VerificationRequest(pydantic.BaseModel):
    hostname: str


@app.post("/verify/")
def verify_hostname(verification_req: VerificationRequest) -> VerificationResult:
    result = verify(verification_req.hostname, openssl=OPENSSL_PATH)
    return result