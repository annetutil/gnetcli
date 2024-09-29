FROM golang:1.20.0 as build
ADD . /build
WORKDIR /build
RUN CGO_ENABLED=0 go build ./cmd/gnetcli_server/

FROM alpine
ENV BASIC_AUTH="mylogin:mysecret"
COPY --from=build /build/server /app/
ENTRYPOINT [ "/app/server" ]
CMD [ "-debug" ]
