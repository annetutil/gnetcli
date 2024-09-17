FROM ubuntu:20.04

RUN apt-get update && apt-get install --no-install-recommends -y \
    ca-certificates \
    clang-format \
    unzip \
    wget \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash docker
USER docker

ENV HOME /home/docker
WORKDIR ${HOME}

ENV LOCAL ${HOME}/.local
RUN mkdir -p ${LOCAL}/bin
ENV PATH $PATH:${LOCAL}/bin

ARG PROTOC_VERSION
RUN wget https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip \
    && unzip protoc-${PROTOC_VERSION}-linux-x86_64.zip -d ${LOCAL}/protoc \
    && rm protoc-${PROTOC_VERSION}-linux-x86_64.zip
ENV PATH $PATH:${LOCAL}/protoc/bin

#ARG BUF_VERISON
#RUN wget https://github.com/bufbuild/buf/releases/download/v${BUF_VERISON}/buf-Linux-x86_64 \
#    && chmod +x buf-Linux-x86_64 \
#    && mv buf-Linux-x86_64 ${LOCAL}/bin/buf
#RUN wget https://github.com/bufbuild/buf/releases/download/v${BUF_VERISON}/protoc-gen-buf-check-lint-Linux-x86_64 \
#    && chmod +x protoc-gen-buf-check-lint-Linux-x86_64 \
#    && mv protoc-gen-buf-check-lint-Linux-x86_64 ${LOCAL}/bin/protoc-gen-buf-check-lint

ARG GO_VERSION
RUN wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C ${LOCAL} -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz
ENV GOPATH ${HOME}/go
ENV PATH $PATH:${LOCAL}/go/bin:$GOPATH/bin

ARG PROTOC_GEN_GO_VERSION
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v${PROTOC_GEN_GO_VERSION}

ARG PROTOC_GEN_GO_GRPC_VERSION
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v${PROTOC_GEN_GO_GRPC_VERSION}

RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --break-system-packages grpcio==1.66.1 grpcio-tools==1.66.1 protobuf==5.28.1
RUN python3 -m grpc_tools.protoc --help
