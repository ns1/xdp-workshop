KERNEL_TARGET = layer3_kern
USER_TARGET = layer3_user

EXTRA_HEADERS = $(wildcard ../00-common/*.h)

USER_TARGET_DEPS = layer3_user.h $(EXTRA_HEADERS)
KERNEL_TARGET_DEPS = $(EXTRA_HEADERS)

CFLAGS = "-I../00-common/"

include ../../common/makerules
