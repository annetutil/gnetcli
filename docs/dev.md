### Build docs

```shell
echo "FROM squidfunk/mkdocs-material
RUN pip install mkdocs-mermaid2-plugin" > Dockerfile
docker build -t gnetclimkdocs .
# build docs to site/
docker run --rm -it -v ${PWD}:/docs gnetclimkdocs build
```

### Build pypi package for gnetcli-server client
```shell
cd grpc_sdk/python
make publish-test
```
