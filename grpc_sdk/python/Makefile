build:
	python3 setup.py sdist

publish-test: build
	twine upload -r testpypi dist/*
