FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY . .

RUN go build -o /app/auth-service

FROM scratch

ENV PORT=3000

EXPOSE ${PORT}

COPY --from=builder /app/auth-service /app/auth-service

ENTRYPOINT ["/app/auth-service"]

