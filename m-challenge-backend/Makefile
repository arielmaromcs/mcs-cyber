.PHONY: help dev build start db-push db-migrate db-seed db-studio docker-up docker-down clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

dev: ## Start development server with hot-reload
	npm run dev

build: ## Build TypeScript
	npm run build

start: ## Start production server
	npm run start

db-push: ## Push schema to database (no migration files)
	npx prisma db push

db-migrate: ## Create and run migration
	npx prisma migrate dev

db-seed: ## Seed the database with demo data
	npx tsx prisma/seed.ts

db-studio: ## Open Prisma Studio (GUI)
	npx prisma studio

docker-up: ## Start all services with Docker Compose
	docker compose up --build -d
	@echo ""
	@echo "M-Challenge Backend is starting..."
	@echo "  API:       http://localhost:3001"
	@echo "  Health:    http://localhost:3001/health"
	@echo "  Postgres:  localhost:5432"
	@echo "  Redis:     localhost:6379"

docker-down: ## Stop all Docker services
	docker compose down

docker-logs: ## Tail Docker logs
	docker compose logs -f backend

clean: ## Remove build artifacts
	rm -rf dist node_modules

install: ## Install dependencies
	npm install

setup: install db-push db-seed ## Full setup: install, create DB, seed
	@echo "Setup complete! Run 'make dev' to start."

test: ## Run smoke tests against running server
	bash scripts/smoke-test.sh

test-url: ## Run smoke tests against custom URL (e.g. make test-url URL=http://host:3001)
	bash scripts/smoke-test.sh $(URL)
