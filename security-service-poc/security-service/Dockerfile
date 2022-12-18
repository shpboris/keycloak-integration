##
## Build
##
FROM golang:1.18-bullseye AS build


WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go build -o security-service .
WORKDIR /dist
RUN cp /build/security-service .

##
## Deploy
##
FROM gcr.io/distroless/base-debian10

WORKDIR /
COPY --from=build /dist/security-service /
EXPOSE 8080
ENTRYPOINT ["/security-service"]