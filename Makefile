ROOT = ../..
PROJECT = zkeycloak
KZ_VERSION = $(shell grep vsn src/zkeycloak.app.src | awk -F\" '{print $$2}')

all: compile

#check_kazoo_env:
#	if grep -q "NLS_LANG" $(ROOT)/rel/kazoo; then \
#	  echo "NLS_LANG exported"; \
#	else \
#	  echo "" >> $(ROOT)/rel/kazoo; \
#	  echo "DEPS += podbc" >> $(ROOT)/make/deps.mk; \
#	  echo "dep_podbc = git https://github.com/onnet/podbc" >> $(ROOT)/make/deps.mk; \
#	  echo "" >> $(ROOT)/make/deps.mk; \
#	fi


include $(ROOT)/make/kz.mk
