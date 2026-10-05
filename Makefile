HOST ?= http://localhost:6060
REDIRECT_URI ?= http://localhost:5050/auth/redirect
USER ?= donor
EMAIL ?= a@b.com
NONCE ?= abc123
STATE ?= xzy789
VTR ?= ["Cl.Cm.P2"]
CLAIMS ?= {"userinfo":{"https://vocab.account.gov.uk/v1/coreIdentityJWT": null,"https://vocab.account.gov.uk/v1/returnCode": null,"https://vocab.account.gov.uk/v1/address": null}}

.PHONY: openid-config openid-config-internal authorize-identity token user-info flow-identity

openid-config:
	curl -sS $(HOST)/.well-known/openid-configuration | jq

openid-config-internal:
	curl -sS '$(HOST)/.well-known/openid-configuration?host=internal' | jq

authorize-identity:
	curl -i -X POST $(HOST)/authorize \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-d 'user=$(USER)' \
		-d 'email=$(EMAIL)' \
		-d 'nonce=$(NONCE)' \
		-d 'state=$(STATE)' \
		-d 'vtr=$(VTR)' \
		-d 'redirect_uri=$(REDIRECT_URI)' \
		-d 'subject=email' \
		-d 'claims=$(CLAIMS)'

token:
ifndef code
	$(error requires code e.g. make token code=code-abc123)
endif
	curl -i -X POST $(HOST)/token \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-d 'code=${code}'

user-info:
ifndef token
	$(error requires token e.g. make user-info token=token-abc123)
endif
	curl -i $(HOST)/userinfo \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-H "Authorization: Bearer $${token}"

flow-identity:
	@set -eu; \
	echo "\n/authorize\n"; \
	response=$$(curl -sS -D - -o /dev/null -X POST $(HOST)/authorize \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-d 'user=$(USER)' \
		-d 'email=$(EMAIL)' \
		-d 'nonce=$(NONCE)' \
		-d 'state=$(STATE)' \
		-d 'vtr=$(VTR)' \
		-d 'redirect_uri=$(REDIRECT_URI)' \
		-d 'subject=email' \
		-d 'claims=$(CLAIMS)'); \
	echo "$$response"; \
	code=$$(printf '%s\n' "$$response" | sed -n 's/^Location: .*code=\([^&]*\).*/\1/p' | tr -d '\r'); \
	if [ -z "$$code" ]; then echo 'failed to extract auth code'; exit 1; fi; \
	echo "code=$$code"; \
	echo "\n/token\n"; \
	token_json=$$(curl -sS -X POST $(HOST)/token -H 'Content-Type: application/x-www-form-urlencoded' -d "code=$$code"); \
	echo "$$token_json" | jq; \
	access_token=$$(printf '%s' "$$token_json" | jq -r '.access_token'); \
	if [ -z "$$access_token" ] || [ "$$access_token" = "null" ]; then echo 'failed to extract access token'; exit 1; fi; \
	echo "\n/userinfo\n"; \
	curl -sS $(HOST)/userinfo -H "Authorization: Bearer $$access_token" | jq
