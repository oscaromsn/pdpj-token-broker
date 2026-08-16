# Convenience targets for the browser service. Run from the container/ dir.
# The image builds from the repo root, so the compose/build context is `..`.

IMAGE ?= pdpj-browser:latest

.PHONY: build up down logs health token deploy-fly

build:            ## Build the image (from the repo root context)
	docker build -f Dockerfile -t $(IMAGE) ..

up:               ## Build + run via docker compose (needs BROWSER_SERVICE_TOKEN)
	docker compose up --build -d

down:             ## Stop and remove
	docker compose down

logs:             ## Tail logs
	docker compose logs -f browser

health:           ## Check liveness on the published port
	curl -fsS http://127.0.0.1:8080/health && echo

token:            ## Generate a shared token to put in .env and the broker
	@openssl rand -base64 32

deploy-fly:       ## Deploy to Fly (run `fly launch --no-deploy` once first)
	fly deploy --dockerfile Dockerfile
