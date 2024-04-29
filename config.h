#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#include "types.h"

#define VERSION "v1"
//terminal color
#define USE_COLOR
//escape ansi
#define FANCY_BOXES
//(milliseconds) timeout for fuzzed code. used for detecting hangs; the actual value is auto-scaled
#define EXEC_TIMEOUT  1000
//(milliseconds) timeout rounding. when auto-scaling 
#define EXEC_TM_ROUND 20
//64bit arch
#if (defined (__x86_64__) || defined (__arm64__) || defined (__aarch64__))
#define WORD_SIZE_64 1
#endif
//(MB) Default memory limit for child process
#ifndef WORD_SIZE_64
#  define MEM_LIMIT         25
#else
#  define MEM_LIMIT         50
#endif
//(MB) memory limit for QEMU mode
#define MEM_LIMIT_QEMU      200
//about calibration 
#define CAL_CYCLES          8
#define CAL_CYCLES_LONG     40
//number of timeout. abandon input file
#define TMOUT_LIMIT         250
//max number
#define KEEP_UNIQUE_HANG    500
#define KEEP_UNIQUE_CRASH   5000
//baseline number of tweaks
#define HAVOC_CYCLES        256
#define HAVOC_CYCLES_INIT   1024
//max multiplier above
#define HAVOC_MAX_MULT      16
//minimum number of havoc cycles
#define HAVOC_MIN           16
//2^1~2^7,stacked tweaks
#define HAVOC_STACK_POW2    7
//block size havoc will pick (33%)
#define HAVOC_BLK_SMALL     32
#define HAVOC_BLK_MEDIUM    128
#define HAVOC_BLK_LARGE     1500
//rarely (<5%)
#define HAVOC_BLK_XL        32768
//(%) probabilities of skipping non-favored
#define SKIP_TO_NEW_PROB    99 /* ...have new favs, pending favorites */
#define SKIP_NFAV_OLD_PROB  95 /* ...no new favs, cur entry already fuzzed */
#define SKIP_NFAV_NEW_PROB  75 /* ...no new favs, cur entry not fuzzed yet */
//splice cycle
#define SPLICE_CYCLES       15
//splice length
#define SPLICE_HAVOC        32
//max offset for add/sub
#define ARITH_MAX           35
//min chunk size;when to chop up the input file 
#define TRIM_MIN_BYTES      4
#define TRIM_START_STEPS    16
#define TRIM_END_STEPS      1024
//(byte) max size of input
#define MAX_FILE            (1 * 1024 * 1024)
//test case
#define TMIN_MAX_FILE       (10 * 1024 * 1024)
//block normalization step afl-tmin
#define TMIN_SET_MIN_SIZE   4
#define TMIN_SET_STEPS      128
//(byte) max dic token size
#define MAX_DICT_FILE       128
//auto detected dictionary token length
#define MIN_AUTO_EXTRA      3
#define MAX_AUTO_EXTRA      32
//max number of deterministic;"extras/user" will lower odds
#define MAX_DET_EXTRAS      200
//max number auto-extracted dictionary tokens actually use in fuzzing
#define USE_AUTO_EXTRAS     50
#define MAX_AUTO_EXTRAS     (USE_AUTO_EXTRAS * 10)
//(2^3) effector map used to skip some of the more expensive deterministic steps
#define EFF_MAP_SCALE2      3
//min length to kick in effector
#define EFF_MIN_LEN         128
//(%) max density 
#define EFF_MAX_PERC        90
//(Hz) ui frequency
#define UI_TARGET_HZ        5
//(sec) stats file and plot 
#define STATS_UPDATE_SEC    60
#define PLOT_UPDATE_SEC     5
//Smoothing divisor
#define AVG_SMOOTHING       16
//Sync interval (every n havoc cycles)
#define SYNC_INTERVAL       5
//(minutes) Output directory reuse grace period
#define OUTPUT_GRACE        25
//interesting number
#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */

//interval between reseeding the libc PRNG from /dev/urandom
#define RESEED_RNG          10000
//max line passed from GCC to 'as' and used for parsing configuration files
#define MAX_LINE            8192
//used to pass SHM ID to the called program
#define SHM_ENV_VAR         "__AFL_SHM_ID"

//only internal
#define CLANG_ENV_VAR       "__AFL_CLANG_MODE"
#define AS_LOOP_ENV_VAR     "__AFL_AS_LOOPCHECK"
#define PERSIST_ENV_VAR     "__AFL_PERSISTENT"
#define DEFER_ENV_VAR       "__AFL_DEFER_FORKSRV"
//In-code signatures for deferred and persistent mode
#define PERSIST_SIG         "##SIG_AFL_PERSISTENT##"
#define DEFER_SIG           "##SIG_AFL_DEFER_FORKSRV##"

//bitmap signature used to indicate failed execution
#define EXEC_FAIL_SIG       0xfee1dead
//exit code used to indicate MSAN trip condition
#define MSAN_ERROR          86
//file descriptors for forkserver commands
#define FORKSRV_FD          198
//Fork server init timeout multiplier: we'll wait the user-selected timeout plus this much
#define FORK_WAIT_MULT      10
//(%) (ms) Calibration timeout
#define CAL_TMOUT_PERC      125
#define CAL_TMOUT_ADD       50
//chances to calibrate a case before giving up
#define CAL_CHANCES         3
//Map size for the traced binary
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
//max allocator request size
#define MAX_ALLOC           0x40000000
//made-up hashing seed
#define HASH_CONST          0xa5b35705
//for afl-gotcpu to control busy loop timing
#define  CTEST_TARGET_MS    5000
#define  CTEST_CORE_TRG_MS  1000
#define  CTEST_BUSY_CYCLES  (10 * 1000 * 1000)

#endif