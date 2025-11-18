import os
import uuid
import logging
from typing import Annotated, Literal, Optional

import pydantic
from fastapi import FastAPI, Request, Response, Header, Depends, Query
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

from smtp_dane_verify.verification import (
    verify, VerificationResult,
    verify_domain_servers, DomainVerificationResult,
)

log = logging.getLogger("uvicorn.error")

DESCRIPTION = '''
This is API verifies TLSA Resource Records, used for DANE with e-mail servers.

This project is sponsored by sys4 AG, Germany
'''
API_TITLE = "SMTP-TLSA Resource Record Verification API"
API_VERSION = "0.2.0"


app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=DESCRIPTION,
    # Disable unauthenticated access to docs
    docs_url=None, redoc_url=None, openapi_url=None
)


OPENSSL_PATH = os.environ.get('OPENSSLPATH', None)
API_KEY = os.environ.get('APIKEY', None)
NAMESERVER = os.environ.get('NAMESERVER', None)
ENV_NO_STRICT_DNSSEC = os.environ.get('NO_STRICT_DNSSEC', 'False')

if API_KEY is None:
    API_KEY = str(uuid.uuid4())
    log.warning(f'*** EnvVar "APIKEY=..." not found, API key will automatically be set to: {API_KEY}')
API_KEYS = [API_KEY]

EXTERNAL_RESOLVER=None
if NAMESERVER is not None:
    EXTERNAL_RESOLVER = NAMESERVER.strip()
    log.info(f'Will use external nameserver `{EXTERNAL_RESOLVER}`')

NO_STRICT_DNSSEC = False
if ENV_NO_STRICT_DNSSEC.strip().lower() in ['true', 'on', 'yes', '1']:
    log.info('NO_STRICT_DNSSEC is true, strict DNSSEC checking will be disabled.')
    NO_STRICT_DNSSEC = True


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
    url = request.url
    return {"message": f"Welcome to the SMTP TLSA Resource Record verification service. Please see docs: {url.scheme}://{url.netloc}{os.path.join(url.path, '/docs/')}"}


class HostnameVerificationRequest(pydantic.BaseModel):
    hostname: str


class DomainVerificationRequest(pydantic.BaseModel):
    """
    Mostly the same as HostnameVerificationRequest, but used when verifying
    a whole domain.
    """
    domain: str


class OpenMetricsResponse(Response):
    media_type = "application/openmetrics-text; version=1.0.0; charset=utf-8"

    def render(self, content: VerificationResult) -> bytes:
        if type(content) == DomainVerificationResult:
            text = "# TYPE dane_smtp_domain_verified gauge\n" \
                   "# HELP dane_smtp_domain_verified Results of the DANE SMTP domain verification\n"
            text += f'dane_smtp_domain_verified{{domain="{content.domain}"}} {1 if content.all_hosts_dane_verified else 0}\n'
        else:
            text = "# TYPE dane_smtp_host_verified gauge\n" \
                   "# HELP dane_smtp_host_verified Results of the DANE SMTP verification\n"
            text += f'dane_smtp_host_verified{{hostname="{content.hostname}"}} {1 if content.host_dane_verified else 0}\n'
        
        return text.encode('utf-8')


def format_output(
        result: VerificationResult|DomainVerificationResult,
        format_name: str|None = None,
        accept_header: str|None=None) -> Response|OpenMetricsResponse|VerificationResult|DomainVerificationResult:
    """
    Format the result object according to the user-specified output format.
    The default is JSON.

    Other options:
        - text
        - openmetrics / prometheus
    """
    response_format = 'json'

    if format_name is not None:
        if format_name == 'text':
            response_format = 'text'
        elif format_name == 'openmetrics' or format_name == 'prometheus':
            response_format = 'openmetrics'
        else:
            response_format = 'json'
    elif accept_header is not None:
        if accept_header.startswith('application/openmetrics-text'):
            response_format = 'openmetrics'
        if accept_header.startswith('text/plain'):
            response_format = 'text'
        if accept_header.startswith('application/json'):
            response_format = 'json'

    if response_format == 'openmetrics':
        return OpenMetricsResponse(content=result)
    elif response_format == 'text':
        return Response(f"{result}\n".encode('utf-8'), media_type="text/plain")
    # default: JSON
    else:
        return result


class QueryParams(pydantic.BaseModel):
    format: Optional[Literal['json', 'text', 'openmetrics', 'prometheus']] = pydantic.Field(None, description="Output format (query parameter), default: JSON")


ACCEPT_HEADER_HELP_TEXT = "HTTP 'Accept' header, equivalent to the ?format=... parameter but takes a " \
                          "MIME type, e.g. application/openmetrics-text"


@app.post("/verify_host/", response_model=VerificationResult)
def verify_hostname(verification_req: HostnameVerificationRequest,
                    query_params: Annotated[QueryParams, Query()],
                    accept: Annotated[str | None, Header(alias='Accept', description=ACCEPT_HEADER_HELP_TEXT)] = None,
                    api_key_header: str = Depends(api_key_header),
                    api_key_query: str = Depends(api_key_query)) -> VerificationResult:
    # Authentication
    check_api_key(api_key_query, api_key_header)

    # Do the actual verification
    result = verify(verification_req.hostname, 
                    openssl=OPENSSL_PATH,
                    external_resolver=EXTERNAL_RESOLVER,
                    disable_dnssec=NO_STRICT_DNSSEC)
    
    # Return the result in the user-specified format
    return format_output(result, query_params.format, accept)



@app.post("/verify/")
def verify_domain(verification_req: DomainVerificationRequest,
                  query_params: Annotated[QueryParams, Query()],
                  accept: Annotated[str | None, Header(alias="Accept", description=ACCEPT_HEADER_HELP_TEXT)] = None,
                  api_key_header: str = Depends(api_key_header),
                  api_key_query: str = Depends(api_key_query)) -> DomainVerificationResult:
    # Authentication
    check_api_key(api_key_query, api_key_header)

    # Do the actual work
    result = verify_domain_servers(verification_req.domain, 
                           openssl=OPENSSL_PATH,
                           external_resolver=EXTERNAL_RESOLVER,
                           disable_dnssec=NO_STRICT_DNSSEC)

    # Return the result in the user-specified format
    return format_output(result, query_params.format, accept)

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
