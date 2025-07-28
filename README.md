# smtp-tlsa-verify

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