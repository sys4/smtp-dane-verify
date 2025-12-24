import os
import uuid
import logging
import asyncio
from typing import Annotated, Literal, Optional
from contextlib import asynccontextmanager

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
API_VERSION = "0.3.2"

# Used to store the last results to be scraped by Prometheus when
# the /metrics endpoint is active.
last_metrics_results: list[DomainVerificationResult]|None = None

# Run
@asynccontextmanager
async def lifespan(app: FastAPI):
    raw_domains = os.environ.get('METRICS_DOMAINS')
    if raw_domains is not None:
        domains = [x.strip().lower() for x in raw_domains.split(',')]
        interval = int(os.environ.get('METRICS_INTERVAL', '600'))
        log.info("Starting metrics background task (interval: %d s) for the following domains: %s" % (interval,", ".join(domains)))
        asyncio.create_task(background_task(domains, interval))
    yield


async def background_task(domains: list, interval: int) -> None:
    """
    Docstring for background_task
    
    :param domains: Description
    :type domains: list
    :param interval: Description
    :type interval: int
    """
    global last_metrics_results
    while asyncio.get_running_loop().is_running:
        new_metrics_results = []
        for domain in domains:
            log.debug("Background task checking %s" % domain)
            def do_work(domain):
                try:
                    return verify_domain_servers(
                        domain, 
                        openssl=OPENSSL_PATH,
                        external_resolver=EXTERNAL_RESOLVER,
                        disable_dnssec=NO_STRICT_DNSSEC
                    )
                except Exception as e:
                    log.error(str(e))
            one_result = await asyncio.get_running_loop().run_in_executor(None, do_work, domain)
            new_metrics_results.append(one_result)
            # Requests to metrics should not be blocked indefinitely.
            await asyncio.sleep(0)
        last_metrics_results = new_metrics_results
        await asyncio.sleep(interval)


app = FastAPI(
    lifespan=lifespan,
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
    
    def __init__(self, content = None, status_code = 200, headers = None, media_type = None, background = None):
        self.metrics = {
            "smtp_dane_verify_version": {
                "HELP": "Information about the smtp-dane-verify version",
                "TYPE": "gauge"
            },
            "smtp_dane_verify_all_hosts_dane_verified": {
                "HELP": "Information if all host of domain are DANE verified",
                "TYPE": "gauge"
            },
            "smtp_dane_verify_dnssec_valid": {
                "HELP": "Information if all DNS records from domain are DNSSEC verified",
                "TYPE": "gauge"
            },
            "smtp_dane_verify_total_mx": {
                "HELP": "Total count of MX-records in domain",
                "TYPE": "gauge"
            },
            "smtp_dane_verify_total_tlsa_openssl_ok": {
                "HELP": "Total count of TLSA-records verified by OpenSSL",
                "TYPE": "gauge"
            },
            "smtp_dane_verify_num_tlsa": {
                "HELP": "Count of TLSA-Records for MX host",
                "TYPE": "gauge"
            },
            "smtp_dane_verify_num_tlsa_dane_ta": {
                "HELP": "Count of DANE-TA TLSA-Records for mail host (Usage 2)",
                "TYPE": "gauge"
            },
            "smtp_dane_verify_num_tlsa_dane_ee": {
                "HELP": "Count of DANE-EE TLSA-Records for mail host (Usage 3)",
                "TYPE": "gauge"
            },
            # Only sometimes used for single-host results, will be ommitted most of the time.
            'dane_smtp_host_verified': {
                'HELP': 'Results of the DANE SMTP verification',
                'TYPE': 'gauge'
            },
        }
        super().__init__(content, status_code, headers, media_type, background)


    def add_val(self, name: str, tag: str, value: str|int) -> None:
        metric = self.metrics[name]
        if not 'VALS' in metric.keys():
            metric['VALS'] = {
                tag: str(value)
            }
        else:
            metric['VALS'][tag] = value
    
    def render_metrics(self) -> str:
        text = ''
        for name, entry in self.metrics.items():
            values = entry.get('VALS', [])
            if len(values) > 0:
                text += f'# HELP {name} {entry['HELP']}\n'
                text += f'# TYPE {name} {entry['TYPE']}\n'
                for tag, value in values.items():
                    text += f'{name}{{{tag}}} {value}\n'
        text += "# EOF"
        return text
    
    def render(self, content: list[VerificationResult|DomainVerificationResult]) -> bytes:
        for result in content:
            if type(result) == DomainVerificationResult:
                self.add_val('smtp_dane_verify_version', f'version="{API_VERSION}"', 1)
                domain = f'domain="{result.domain}"'
                self.add_val('smtp_dane_verify_all_hosts_dane_verified', domain, 1 if result.all_hosts_dane_verified else 0)
                self.add_val('smtp_dane_verify_dnssec_valid', domain, 1 if result.dnssec_valid else 0)
                self.add_val('smtp_dane_verify_total_mx', domain, len(result.mx_hosts))
                total_tlsa_resource_records = 0
                for mx_host in result.mx_hosts:
                    total_tlsa_resource_records += len(mx_host.tlsa_resource_records)
                self.add_val('smtp_dane_verify_total_tlsa_openssl_ok', domain, total_tlsa_resource_records)
                for mx_host in result.mx_hosts:
                    mx = f'mx="{mx_host.hostname}"'
                    self.add_val('smtp_dane_verify_num_tlsa', mx, len(mx_host.tlsa_resource_records))
                    self.add_val(
                        'smtp_dane_verify_num_tlsa_dane_ta', 
                        mx, 
                        len([record for record in mx_host.tlsa_resource_records if record.startswith('2')])
                    )
                    self.add_val(
                        'smtp_dane_verify_num_tlsa_dane_ee',
                        mx,
                        len([record for record in mx_host.tlsa_resource_records if record.startswith('3')])
                    )
                text = self.render_metrics()
            elif type(result) == VerificationResult:
                self.add_val('smtp_dane_verify_version', f'version="{API_VERSION}"', 1)
                self.add_val('dane_smtp_host_verified', 'hostname="{result.hostname}"', 1 if result.host_dane_verified else 0)
            else:
                raise Exception()

        # OpenMetrics.io specs require UTF-8
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
        # OpenMetricsResponse requires a **list** of DomainVerificationResults
        return OpenMetricsResponse(content=[result])
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


@app.get('/metrics')
def get_metrics(api_key_header: str = Depends(api_key_header),
                api_key_query: str = Depends(api_key_query)) -> Response:
    global last_metrics_results

    # Authentication
    check_api_key(api_key_query, api_key_header)

    # Error handling
    if last_metrics_results is None or len(last_metrics_results) == 0:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service is currently unavailable. Please try again later."
        )
    return OpenMetricsResponse(content=last_metrics_results)


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
