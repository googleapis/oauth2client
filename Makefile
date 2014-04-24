pep8:
	find apiclient samples -name "*.py" | xargs pep8 --ignore=E111,E202

APP_ENGINE_PATH=../google_appengine

test:
	tox

.PHONY: coverage
coverage:
	coverage erase
	find tests -name "test_*.py" | xargs --max-args=1 coverage run -a runtests.py
	coverage report
	coverage html

.PHONY: docs
docs:
	cd docs; ./build

.PHONY: prerelease
oauth2_prerelease: test
	-rm -rf dist/
	-sudo rm -rf dist/
	-rm -rf snapshot/
	-sudo rm -rf snapshot/
	mkdir snapshot
	python expandsymlinks.py
	cd snapshot; python setup.py clean
	cd snapshot; python setup.py sdist --formats=gztar,zip

.PHONY: release
oauth2_release: oauth2_prerelease
	@echo "This target will upload a new release to PyPi."
	@echo "Are you sure you want to proceed? (yes/no)"
	@read yn; if [ yes -ne $(yn) ]; then exit 1; fi
	@echo "Here we go..."
	cd snapshot; python setup.py sdist --formats=gztar,zip register upload
