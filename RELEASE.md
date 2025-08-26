# How To Release a New Version 

This is a checklist / list of steps meant for the maintainer of this package.

## Release on PyPI

- Change the version number in pyproject.toml
- Change the version number in smtp_dane_verify/api.py
- run `uv build`
- run `uv publish`
- enter `__token__` as username
- enter the `upload-smtp-tlsa-verify` token and watch the files be uploaded.
- remove/clean the `dist/` subdir.

## Release on DockerHub

- `docker build -t smtp-dane-verify .`
- `docker login`
- `docker push ...`
- `docker logout`