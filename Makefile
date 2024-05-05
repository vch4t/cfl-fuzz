PROGNAME 	= cfl
VERSION  	= $(shell grep '^\#define VERSION ' config.h | cut -d '"' -f2)
PREFIX     ?= $(shell pwd)/test

BIN_PATH    = $(PREFIX)
HELPER_PATH = $(PREFIX)
DOC_PATH    = $(PREFIX)
MISC_PATH   = $(PREFIX)

PROGS		= afl-gcc
CFLAGS		?= -O3 -funroll-loops
CFLAGS		+= -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\" \
	      -DBIN_PATH=\"$(BIN_PATH)\"

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

ifeq "$(findstring clang, $(shell $(CC) --version 2>/dev/null))" ""
  TEST_CC   = afl-gcc
else
  TEST_CC   = afl-clang
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h

all: test_x86 $(PROGS) afl-as test_build all_done

ifndef AFL_NO_X86
test_x86:
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'main() { __asm__("xorb %al, %al"); }' | $(CC) -w -x c - -o .test || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "Don't panic! You can use the LLVM or QEMU mode, but see docs/INSTALL first."; echo "(To ignore this error, set AFL_NO_X86=1 and try again.)"; echo; exit 1 )
	@rm -f .test
	@echo "[+] Everything seems to be working, ready to compile."
else
test_x86:
	@echo "[!] Note: skipping x86 compilation checks (AFL_NO_X86 set)."
endif

afl-gcc:afl-gcc.c $(COMM_HDR) |test_x86
	$(CC) $(CFLAGS) $@.c -o test/$@ $(LDFLAGS)
	set -e; for i in test/afl-g++ test/afl-clang test/afl-clang++; do ln -sf afl-gcc $$i; done
afl-as: afl-as.c afl-as.h $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o test/$@ $(LDFLAGS)
	ln -sf afl-as test/as

clean:
	rm -f $(PROGS) afl-as as afl-g++ afl-clang afl-clang++ *.o *~ a.out core core.[1-9][0-9]* *.stackdump .test
clean_test:
	rm -f test/$(PROGS) test/afl-as test/as test/afl-g++ test/afl-clang test/afl-clang++ test/*.o test/a.out
test1:
	echo $(TEST_CC)