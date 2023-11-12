clean:
	rm -fr dist gnetclisdk.egg-info

build:
	python3 setup.py -v sdist

publish-test: clean build
	twine upload -r testpypi dist/*

publish-prod: clean build
	twine upload -r pypi dist/*
