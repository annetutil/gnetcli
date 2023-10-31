from setuptools import setup

with open("README.md") as f:
    readme = f.read()

with open("../../LICENSE") as f:
    license = f.read()

with open("requirements.txt") as f:
    requirements = f.read()

setup(
    name="gnetclisdk",
    version="1.0.0",
    description="Gnetcli GRPC-server SDK",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Alexander Balezin",
    author_email="gescheit12@gmail.com",
    url="https://github.com/annetutil/gnetcli",
    license=license,
    packages=[
        "gnetclisdk",
    ],
    package_dir={"gnetclisdk": "../../pkg/server/proto"},
    package_data={"gnetclisdk": ["../../pkg/server/proto/*.py"]},
    include_package_data=True,
    install_requires=list(requirements.splitlines()),
)
