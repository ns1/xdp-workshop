KERNEL_TARGET = layer4_kern
USER_TARGET = layer4_user

EXTRA_HEADERS = $(wildcard ../00-common/*.h)

USER_TARGET_DEPS = layer4_user.h $(EXTRA_HEADERS)
KERNEL_TARGET_DEPS = $(EXTRA_HEADERS)

CFLAGS = "-I../00-common/"

include ../../common/makerules
