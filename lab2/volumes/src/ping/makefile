SRCS := $(wildcard *.c)
LIBSRCDIR := ../nslib
LIBSRCS := $(wildcard $(LIBSRCDIR)/*.c)
EXECUTABLES := ping.bin
OBJDIR := build
LIBDIR := lib
OBJS := $(SRCS:%.c=$(OBJDIR)/%.o)

CFLAGS +=  -Werror -Wextra -I$(LIBSRCDIR)
LDLIBS += -lpcap -lnslib
LDFLAGS += -L$(LIBDIR)

all: debug

release: CFLAGS += -O3
release: $(EXECUTABLES)

debug: CFLAGS += -ggdb
debug: $(EXECUTABLES)

$(EXECUTABLES): $(OBJS) $(LIBDIR)/libnslib.a
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(LIBDIR)/libnslib.a: $(LIBSRCS:$(LIBSRCDIR)/%.c=$(LIBDIR)/%.o)
	$(AR) rcs $@ $^

.PHONY: clean all

clean:
	rm -rf $(EXECUTABLES) $(OBJDIR) $(LIBDIR)

## Overriding implicit rules.
##  Taken and adapted from Documentation:
##	https://make.mad-scientist.net/papers/advanced-auto-dependency-generation/


DEPDIR :=$(OBJDIR)/.deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.d

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c

%.o: %.c
$(OBJDIR)/%.o :  %.c $(DEPDIR)/%.d | $(DEPDIR)
	$(COMPILE.c) $(OUTPUT_OPTION) $<

$(LIBDIR)/%.o : $(LIBSRCDIR)/%.c | $(LIBDIR)
	$(COMPILE.c) $(OUTPUT_OPTION) $<

$(DEPDIR) : ; @mkdir -p $@
$(LIBDIR) : ; @mkdir -p $@

DEPFILES := $(SRCS:%.c=$(DEPDIR)/%.d)
$(DEPFILES):

include $(wildcard $(DEPFILES))

