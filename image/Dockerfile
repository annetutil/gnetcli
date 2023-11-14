FROM golang:1.20.0 as build
ADD . /build
WORKDIR /build
RUN CGO_ENABLED=0 go build ./cmd/server/

FROM alpine
COPY --from=build /build/server /app/
ENTRYPOINT [ "/app/server" ]
CMD [ "-basic-auth", "mylogin:mysecret" ]
