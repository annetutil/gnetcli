FROM scratch

LABEL maintainer="Alexander Balezin"
LABEL documentation="https://annetutil.github.io/gnetcli/"
LABEL repo="https://github.com/annetutil/gnetcli"
ENV BASIC_AUTH="mylogin:mysecret"
COPY server /app/server
ENTRYPOINT [ "/app/server" ]
CMD [ "-debug" ]

