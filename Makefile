mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
protoc_cmd := python3 -m grpc_tools.protoc

all: build proto testrace

build:
	go build ./...

build-docker:
	docker build -f ./image/Dockerfile -t gnetcli-server .

build-proto-docker:
	(cd proto_builder; IMAGE=proto_builder TAG=tag make build)

proto:
	docker run --rm -v `pwd`:/home/docker/app --workdir /home/docker/app proto_builder:tag \
		protoc -I ./pkg/server/proto/ \
			--go_opt=paths=source_relative \
			--go-grpc_opt=paths=source_relative \
			--go_out=./pkg/server/proto/ \
			--go-grpc_out=./pkg/server/proto/ \
			'./pkg/server/proto/server.proto'
	docker run --rm -v `pwd`:/home/docker/app --workdir /home/docker/app proto_builder:tag \
		protoc -I ./pkg/server/proto/ --grpc-gateway_out ./pkg/server/proto/ \
			--grpc-gateway_opt paths=source_relative \
			--grpc-gateway_opt generate_unbound_methods=true \
			pkg/server/proto/server.proto
	docker run --rm -v `pwd`:/home/docker/app --workdir /home/docker/app proto_builder:tag \
		$(protoc_cmd) -I ./pkg/server/proto/ \
			 --python_out=./pkg/server/proto/ \
			 --pyi_out=./pkg/server/proto/ \
			 --grpc_python_out=./pkg/server/proto/ \
			 './pkg/server/proto/server.proto'
	perl -pi -e 's,import server_pb2 as server__pb2,from . import server_pb2 as server__pb2,' '${CURDIR}/pkg/server/proto/server_pb2_grpc.py'

testrace:
	go test -v -race -cpu 1,4 ./...

clean:
	go clean -i ./...


.PHONY: \
	all \
	clean
