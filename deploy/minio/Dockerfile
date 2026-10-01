# Local development and integration tests only. MinIO's community distribution
# is source-only; use the official release commit instead of an unavailable image.
FROM golang:1.25-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
RUN git init . \
    && git fetch --depth 1 https://github.com/minio/minio.git 9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a"
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -p 2 -o /out/minio .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
LABEL org.opencontainers.image.source="https://github.com/minio/minio" \
      org.opencontainers.image.revision="9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a"
COPY --from=build /out/minio /usr/local/bin/minio
COPY --from=build /src/LICENSE /usr/share/licenses/minio/LICENSE
EXPOSE 9000 9001
ENTRYPOINT ["/usr/local/bin/minio"]
