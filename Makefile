authorize-identity:
ifdef user
	curl -i -X POST http://localhost:6060/authorize \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-d 'user=${user}' \
		-d 'email=a@b.com' \
		-d 'nonce=abc123' \
		-d 'state=xzy789' \
		-d 'vtr=["Cl.Cm.P2"]' \
		-d 'redirect_uri=http://localhost:5050/auth/redirect' \
		-d 'claims={"userinfo":{"https://vocab.account.gov.uk/v1/coreIdentityJWT": null,"https://vocab.account.gov.uk/v1/returnCode": null,"https://vocab.account.gov.uk/v1/address": null}}'
else
	@echo 'requires user e.g. make authorize-identity user=donor'
endif


token:
ifdef code
	curl -i -X POST http://localhost:6060/token \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d 'code=${code}'
else
	@echo 'requires code e.g. make token code=code-abc123'
endif

user-info:
ifdef token
	curl -i http://localhost:6060/userinfo \
	  -H 'Content-Type: application/x-www-form-urlencoded' \
	  -H "Authorization: Bearer $(token)"
else
	@echo 'requires token e.g. make user-info token=token-abc123'
endif
