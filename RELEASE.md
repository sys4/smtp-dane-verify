# How To Release a New Version 

This is a checklist / list of steps meant for the maintainer of this package.

## Build the release for both Docker.io and PyPI

- Change the version number in pyproject.toml
- Change the version number in smtp_dane_verify/api.py
- Commit and push the changes
- Tag the last commit with `git tag vX.X.X` and push the tags with `git push --tags`
- run `make release`, this will
    - create a Python package for PyPI
    - create a Docker image for linux/amd64 and linux/arm64, tagged with the package version and 'latest'

## Release on PyPI

- run `make publishpypi`, this will call `uv publish`
- enter `__token__` as username
- enter the `upload-smtp-tlsa-verify` token and watch the files be uploaded.

# Release on Docker 
- run `make publishdocker`
- run `make clean` to remove/clean the `dist/` subdir.

DONE!

## Manual release on DockerHub

These are the steps needed to build the package for Docker.io manually:

- `docker build -t sys4ag/smtp-dane-verify:<package-version> .`
- `docker tag sys4ag/smtp-dane-verify:<package-version> latest`
- `docker login`
- `docker push ...`
- `docker logout`
