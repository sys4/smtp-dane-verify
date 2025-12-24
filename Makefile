PKG_VER := $(shell grep 'version = "' pyproject.toml | head -n 1 | cut -d '"' -f 2 )
API_VER := $(shell grep 'API_VERSION' smtp_dane_verify/api.py | head -n 1 | cut -d '"' -f 2 )

.PHONY: release publishpypi docs

README.md: README.adoc
	asciidoctor -b docbook5 -o - README.adoc | pandoc -f docbook -t markdown_strict -o README.md

docs: README.md

release: README.md
	@echo "Package version (pyproject.toml) is $(PKG_VER)"
	@echo "API version (api.py) is defined as $(API_VER)"
ifneq ($(PKG_VER), $(API_VER))
	@echo "API and package version are not equal, aborting package build."
	exit 1
endif
	uv build
	docker buildx build -t sys4ag/smtp-dane-verify:$(PKG_VER) -t sys4ag/smtp-dane-verify:latest --platform linux/amd64,linux/arm64 .
	# docker image tag sys4ag/smtp-dane-verify:$(PKG_VER) sys4ag/smtp-dane-verify:latest

publishpypi: dist/smtp_dane_verify-$(PKG_VER)-py3-none-any.whl dist/smtp_dane_verify-$(PKG_VER).tar.gz
	uv publish
	
publishdocker:
	docker login
	docker push sys4ag/smtp-dane-verify
	docker logout
