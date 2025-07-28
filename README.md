# smtp-tlsa-verify

## Using Docker to run the Micro-API as a Container

```
docker run --rm -p 3000:3000 -e APIKEY=secretapikey sys4ag/smtp-tlsa-verify
```

Then open http://localhost:3000/ in your Browser. You will see an error message.

Add the `api_key` parameter to the URL to get access to the API, for example:

  - http://localhost:3000/docs/?api_key=secretapikey

Using the built-in docs you can interactively 


## Installing and running the FastAPI-based HTTP/JSON service

Install using the `fastapi` extra option:

```
pip install smtp-tlsa-verify[fastapi]
```

or if using the `uv` package manager:

```
uv add smtp-tlsa-verify --extra fastapi
```

## Installing as a command line utility using pipx

```
pipx install smpt-tlsa-verify
```

After installation you can run the following command to verify: `danesmtp mail.example.com`


## Using as a library

```
pip install smtp-tlsa-verify
```

```
from smtp_tlsa_verify import verify

result = verify("mail.example.com")
print(result)
```
