FROM golang:1.21 as build
ADD . /build
WORKDIR /build
RUN CGO_ENABLED=0 go build ./cmd/gnetcli_server/

FROM alpine
ENV BASIC_AUTH="mylogin:mysecret"
COPY --from=build /build/gnetcli_server /app/
ENTRYPOINT [ "/app/gnetcli_server" ]
CMD [ "-debug", "-port", "0.0.0.0:50051" ]
