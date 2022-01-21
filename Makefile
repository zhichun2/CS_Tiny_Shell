#
# Makefile for the CS:APP Shell Lab
#
# Type "make" to build your shell and driver
#
include .labname.mk

# Compiler / linker options
CC = gcc
CFLAGS = -g -O2 -std=gnu11 -Wall -Wextra -Wpedantic \
	 -Wstrict-prototypes -Wno-unused-parameter -Werror
CPPFLAGS = -D_FORTIFY_SOURCE=2 -I.
LDLIBS = -Wl,--as-needed -lpthread

# For tshlab, LLVM is only used for clang-format
LLVM_PATH =
ifneq (,$(wildcard /usr/lib/llvm-7/bin/))
   LLVM_PATH = /usr/lib/llvm-7/bin/
else
 ifneq (,$(wildcard /usr/local/depot/llvm-7.0/bin/))
   LLVM_PATH = /usr/local/depot/llvm-7.0/bin/
 endif
endif


# Functions to interpose in wrapper.c
WRAPCFLAGS :=
WRAPCFLAGS += -Wl,--wrap=fork
WRAPCFLAGS += -Wl,--wrap=kill
WRAPCFLAGS += -Wl,--wrap=killpg
WRAPCFLAGS += -Wl,--wrap=waitpid
WRAPCFLAGS += -Wl,--wrap=execve
WRAPCFLAGS += -Wl,--wrap=execv
WRAPCFLAGS += -Wl,--wrap=execvpe
WRAPCFLAGS += -Wl,--wrap=execvp
WRAPCFLAGS += -Wl,--wrap=tcsetpgrp
WRAPCFLAGS += -Wl,--wrap=signal
WRAPCFLAGS += -Wl,--wrap=sigaction
WRAPCFLAGS += -Wl,--wrap=sigsuspend
WRAPCFLAGS += -Wl,--wrap=sigprocmask
WRAPCFLAGS += -Wl,--wrap=printf
WRAPCFLAGS += -Wl,--wrap=fprintf
WRAPCFLAGS += -Wl,--wrap=sprintf
WRAPCFLAGS += -Wl,--wrap=snprintf
WRAPCFLAGS += -Wl,--wrap=init_job_list
WRAPCFLAGS += -Wl,--wrap=job_get_pid
WRAPCFLAGS += -Wl,--wrap=job_set_state


# Auxiliary programs
HELPER_PROGS :=
HELPER_PROGS += myspin1
HELPER_PROGS += myspin2
HELPER_PROGS += myenv
HELPER_PROGS += myintp
HELPER_PROGS += myints
HELPER_PROGS += mytstpp
HELPER_PROGS += mytstps
HELPER_PROGS += mysplit
HELPER_PROGS += mysplitp
HELPER_PROGS += mycat
HELPER_PROGS += mysleepnprint
HELPER_PROGS += mysigfun
HELPER_PROGS += mytstpandspin
HELPER_PROGS += myspinandtstps
HELPER_PROGS += myusleep

# Prefix all helper programs with testprogs/
HELPER_PROGS := $(HELPER_PROGS:%=testprogs/%)


# List all build targets and header files
HANDIN_TAR = tshlab-handin.tar

FILES = sdriver runtrace tsh $(HELPER_PROGS) $(HANDIN_TAR)
DEPS = config.h csapp.h tsh_helper.h testprogs/helper.h


.PHONY: all
all: $(FILES)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile tsh with link-time interpositioning
tsh: LDFLAGS += $(WRAPCFLAGS)
tsh: tsh.o wrapper.o csapp.o tsh_helper.o

sdriver: sdriver.o
runtrace: runtrace.o csapp.o


# Clean up
.PHONY: clean
clean:
	rm -f *.o *~ $(FILES)
	rm -rf runtrace.tmp


# Include rules for submit, format, etc
FORMAT_FILES = tsh.c
HANDIN_FILES = tsh.c .clang-format
include helper.mk


# Add check-format dependencies
submit: | check-format
tsh $(HANDIN_TAR): | check-format
