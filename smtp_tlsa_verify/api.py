import os
from typing import Union

from fastapi import FastAPI, Request
import pydantic

from smtp_tlsa_verify.verification import verify, VerificationResult

DESCRIPTION = '''
This is API verifies TLSA Resource Records, used for DANE with e-mail servers.

This project is shttp://localhost:8000/docs/ponsored by sys4 AG, Germany
'''

app = FastAPI(
    title="SMTP-TLSA Resource Record Verification API",
    version='1.0.0',
    description=DESCRIPTION,
)


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