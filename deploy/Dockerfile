# The builder pins the same toolchain as go.mod and CI. A floating tag would
# reintroduce the version drift the pin exists to prevent.
FROM golang:1.25.12-alpine AS build

WORKDIR /src

# Dependencies are copied first so a source-only change does not refetch them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is off so the binary runs in a scratch-style image with no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authd ./cmd/authd

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/authd /authd
COPY deploy/stellar.toml.example /etc/anchorage/stellar.toml

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/authd"]
