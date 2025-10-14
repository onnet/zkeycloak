ROOT = ../..
PROJECT = zkeycloak
KZ_VERSION = $(shell grep vsn src/zkeycloak.app.src | awk -F\" '{print $$2}')

all: compile

include $(ROOT)/make/kz.mk
