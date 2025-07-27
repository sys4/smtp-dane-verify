import os
import uuid

import pydantic
from fastapi import FastAPI, Request, Depends
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

from smtp_tlsa_verify.verification import verify, VerificationResult

DESCRIPTION = '''
This is API verifies TLSA Resource Records, used for DANE with e-mail servers.

This project is shttp://localhost:8000/docs/ponsored by sys4 AG, Germany
'''
API_TITLE = "SMTP-TLSA Resource Record Verification API"
API_VERSION = "1.0.0"

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=DESCRIPTION,
    # Disable unauthenticated access to docs
    docs_url=None, redoc_url=None, openapi_url=None
)


OPENSSL_PATH = os.environ.get('OPENSSLPATH', None)
API_KEY = os.environ.get('APIKEY', None)

if API_KEY is None:
    API_KEY = str(uuid.uuid4())
    print(f'*** EnvVar "APIKEY=..." not found, API key will automatically be set to: {API_KEY}')

API_KEYS = [API_KEY]


from fastapi import HTTPException, status, Security, FastAPI
from fastapi.security import APIKeyHeader, APIKeyQuery

api_key_query = APIKeyQuery(name="api_key", auto_error=False)
api_key_header = APIKeyHeader(name="x-apikey", auto_error=False)


def check_api_key(
    api_key_query: str = Security(api_key_query),
    api_key_header: str = Security(api_key_header),
) -> str:
    """Retrieve and validate an API key from the query parameters or HTTP header.

    Args:
        api_key_query: The API key passed as a query parameter.
        api_key_header: The API key passed in the HTTP header.

    Returns:
        The validated API key.

    Raises:
        HTTPException: If the API key is invalid or missing.
    """
    if api_key_query in API_KEYS:
        return api_key_query
    if api_key_header in API_KEYS:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )


@app.get("/")
def welcome_message(request: Request, api_key_header: str = Depends(api_key_header), api_key_query: str = Depends(api_key_query)):
    check_api_key(api_key_query, api_key_header)
    print(request.url.components)
    url = request.url
    return {"message": f"Welcome to the SMTP TLSA Resource Record verification service. Please see docs: {url.scheme}://{url.netloc}{os.path.join(url.path, '/docs/')}"}


class VerificationRequest(pydantic.BaseModel):
    hostname: str


@app.post("/verify/")
def verify_hostname(verification_req: VerificationRequest, api_key_header: str = Depends(api_key_header), api_key_query: str = Depends(api_key_query)) -> VerificationResult:
    check_api_key(api_key_query, api_key_header)
    result = verify(verification_req.hostname, openssl=OPENSSL_PATH)
    return result


@app.get("/docs", include_in_schema=False)
async def get_documentation(api_key_header: str = Depends(api_key_header), api_key_query: str = Depends(api_key_query)):
    check_api_key(api_key_query, api_key_header)
    if api_key_query:
        url = f'/openapi.json?api_key={api_key_query}'
    else:
        url = '/openapi.json'
    return get_swagger_ui_html(openapi_url=url, title="docs")


@app.get("/openapi.json", include_in_schema=False)
async def openapi(api_key_header: str = Depends(api_key_header), api_key_query: str = Depends(api_key_query)):
    check_api_key(api_key_query, api_key_header)
    return get_openapi(title=API_TITLE, version=API_VERSION, description=DESCRIPTION, routes=app.routes)
