##
## Build
##
FROM golang:1.18-bullseye AS build


WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go build -o frontend .
WORKDIR /dist
RUN cp /build/frontend .

##
## Deploy
##
FROM gcr.io/distroless/base-debian10

WORKDIR /
COPY --from=build /dist/frontend /
EXPOSE 8080
ENTRYPOINT ["/frontend"]