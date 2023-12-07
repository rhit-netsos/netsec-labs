## Do not mess with anything here.
SRCS := $(wildcard *.c)
LIBSRCDIR := ../nslib
LIBSRCS := $(wildcard $(LIBSRCDIR)/*.c)
OBJDIR := build
LIBDIR := lib

CFLAGS +=  -Werror -Wextra -I$(LIBSRCDIR)
LDLIBS += -lpcap -lnslib
LDFLAGS += -L$(LIBDIR)

## TODO: Add executable here if needed
EXECUTABLES := printpkt.bin printarp.bin

# Do not mess with anything here.
all: debug

release: CFLAGS += -O3
release: $(EXECUTABLES)

debug: CFLAGS += -ggdb
debug: $(EXECUTABLES)

## TODO: Add rules for executables here if needed
printpkt.bin: $(OBJDIR)/printpkt.o $(LIBDIR)/libnslib.a

printarp.bin: $(OBJDIR)/printarp.o $(LIBDIR)/libnslib.a

## Do not mess with anything below here.
$(EXECUTABLES):
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

