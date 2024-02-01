SOURCES		:= auto_tests/send_message_test.c \
		   auto_tests/auto_test_support.c \
		   testing/misc_tools.c \
		   $(wildcard tox*/*.c tox*/*/*.c) \
		   third_party/cmp/cmp.c \
		   alloca.c
OBJECTS		:= $(SOURCES:.c=.o)

CC		:= cproc
CFLAGS		:= $(shell pkg-config --cflags libsodium opus vpx)
LDFLAGS		:= $(shell pkg-config --libs libsodium opus vpx)
CPPFLAGS	:= -DDISABLE_VLA

send_message_test: $(OBJECTS)
	$(CC) -o $@ $+ $(LDFLAGS)
