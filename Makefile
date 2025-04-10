include config.mk
python.envdir = $(CURDIR)/env
python.version ?= 3.13
python = python$(python.version)
python.pip = $(python.envdir)/bin/pip
ifneq ($(wildcard $(python.envdir)/bin/python),)
python = $(python.envdir)/bin/python
endif


env:
	@$(python) -m venv $(python.envdir)
	@$(foreach m, $(python.devmodules), $(python.pip) install -e '$(m)[develop]';)
