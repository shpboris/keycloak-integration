##
## Build
##
FROM golang:1.18-bullseye AS build


WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go build -o auth-proxy .
WORKDIR /dist
RUN cp /build/auth-proxy .

##
## Deploy
##
FROM gcr.io/distroless/base-debian10

WORKDIR /
COPY --from=build /dist/auth-proxy /
EXPOSE 8080
ENTRYPOINT ["/auth-proxy"]