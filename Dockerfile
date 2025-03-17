FROM golang:1.24

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go get github.com/jackc/pgx/v5
RUN go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

RUN sqlc generate

EXPOSE 8080

CMD ["sh", "-c", "migrate -path /app/db/migrations -database \"postgres://postgres:password@postgres:5432/elearning?sslmode=disable\" up && go run main.go"]

