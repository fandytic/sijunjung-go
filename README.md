# Sijunjung Coffee Chat Service

A Go + MongoDB starter service inspired by the coffee-chat-service reference. It exposes bearer-token authentication with login/logout, persists logs to MongoDB, and includes a sample protected API endpoint.

The project follows a simple Clean Architecture layout:
- `internal/domain` holds entities and repository interfaces.
- `internal/usecase/auth` contains authentication business rules.
- `internal/infra` provides Mongo-backed repositories and logging adapters.
- `internal/delivery/http` wires HTTP handlers and middleware.

## Prerequisites
- Go 1.22+
- MongoDB instance accessible at `MONGO_URI`

## Configuration
Environment variables are read from the host and can be sourced via a local `.env` file (copy `.env.example` to `.env`).
- `MONGO_URI` (default `mongodb://localhost:27017`)
- `MONGO_DB` (default `coffeechat`)
- `AUTH_SECRET` (default `changeme`)
- `HTTP_PORT` (default `8080`)

## Running locally
1. Start MongoDB.
2. Create an environment file:
   ```bash
   cp .env.example .env
   ```
3. Install dependencies (requires network access):
   ```bash
   go mod tidy
   ```
4. Generate/update API docs (requires the `swag` CLI):
   ```bash
   go install github.com/swaggo/swag/cmd/swag@v1.16.3
   go generate ./...
   ```
5. Run the server:
   ```bash
   go run ./cmd/server
   ```

## Docker
Build and run the service in a container:
```bash
docker build -t coffee-chat .
docker run --rm -p 8080:8080 --env-file .env coffee-chat
```

## CI/CD
GitHub Actions workflow `.github/workflows/ci.yml` generates Swagger files from annotations, formats code, runs `go vet`, and executes the test suite on pushes and pull requests.

## API documentation
- Interactive docs are available at `/swagger/index.html` once the server is running.
- Documentation is generated from route annotations using `swag init` via `go generate ./...` to keep the spec synced when endpoints change.

## API
- `POST /api/register` – create user (`email`, `password`).
- `POST /api/login` – obtain bearer token.
- `POST /api/logout` – revoke token (requires `Authorization: Bearer <token>`).
- `GET /api/me` – echo authenticated user id.
- `GET /api/coffee` – sample protected endpoint.

Logs are written to stdout and stored in the `logs` MongoDB collection.
