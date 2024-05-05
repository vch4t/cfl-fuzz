#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include "afl-as.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>

static u8** as_params;          /* Parameters passed to the real 'as'   */

static u8*  input_file;         /* Originally specified input file      */
static u8*  modified_file;      /* Instrumented file for the real 'as'  */

static u8   be_quiet,           /* Quiet mode (no stderr output)        */
            clang_mode,         /* Running in clang mode?               */
            pass_thru,          /* Just pass data through?              */
            just_version,       /* Just show version?                   */
            sanitizer;          /* Using ASAN / MSAN                    */

static u32  inst_ratio = 100,   /* Instrumentation probability (%)      */
            as_par_cnt = 1;     /* Number of params to 'as'             */


#ifdef WORD_SIZE_64
static u8   use_64bit = 1;
#else
static u8   use_64bit = 0;
#endif

static void edit_params(int argc, char **argv){
    u8 *tmp_dir = getenv("TMPDIR"),*afl_as = getenv("AFL_AS");
    u32 i;
    if(!tmp_dir) tmp_dir = getenv("TEMP");
    if (!tmp_dir) tmp_dir = getenv("TMP");
    if (!tmp_dir) tmp_dir = "/tmp";
    as_params = ck_alloc((argc+32)*sizeof(u8*));
    as_params[0]=afl_as ? afl_as : (u8*)"as";
    as_params[argc]=0;
    for(i=1;i<argc-1;i++){
        if(!strcmp(argv[i],"--64")) use_64bit=1;
        else if(!strcmp(argv[i],"--32")) use_64bit=0;
        as_params[as_par_cnt++]=argv[i];
    }
    input_file=argv[argc-1];
    if(input_file[0]=='-'){
        if(!strcmp(input_file+1,"-version")){
            just_version=1;
            modified_file=input_file;
            goto wrap_things_up;
        }
        if(input_file[1]){
            FATAL("Incorrect use");
        }
        else{
            input_file=NULL;
        }
    }
    else{
        if (strncmp(input_file, tmp_dir, strlen(tmp_dir)) &&
            strncmp(input_file, "/var/tmp/", 9) &&
            strncmp(input_file, "/tmp/", 5)) pass_thru = 1;
    }
    modified_file=alloc_printf("%s/.afl-%u-%u.s",tmp_dir,getpid(),(u32)time(NULL));
wrap_things_up:
    as_params[as_par_cnt++]=modified_file;
    as_params[as_par_cnt]=NULL;
}
static void add_instrumentation(){
    static u8 line[MAX_LINE];
    FILE* inf;
    FILE* outf;
    s32 outfd;
    u32 ins_lines=0;
    u8  instr_ok = 0, skip_csect = 0, skip_next_label = 0,
      skip_intel = 0, skip_app = 0, instrument_next = 0;
    if(input_file){
        inf=fopen(input_file,"r");
        if(!inf){
            PFATAL("Unable to read");
        }
    }
    else{
        inf =stdin;
    }
    outfd=open(modified_file,O_WRONLY|O_EXCL|O_CREAT,0600);
    if(outfd<0){
        PFATAL("unable to write");
    }
    outf=fdopen(outfd,"w");
    if(!outf){
        PFATAL("fdopen() failed");
    }
    while(fgets(line,MAX_LINE,inf)){
        //add after all labels, macros, etc.
        if(!pass_thru&&!skip_intel&&!skip_csect&&instr_ok&&instrument_next&&
            line[0]=='\t'&&isalpha(line[1])){
                fprintf(outf,use_64bit?trampoline_fmt_64:trampoline_fmt_32,
                        R(MAP_SIZE));
                instrument_next=0;
                ins_lines++;
        }
        fputs(line,outf);
        if(pass_thru){
            continue;
        }
        if(line[0]=='\t'&&line[1]=='.'){
            if(!clang_mode&&instr_ok&&!strncmp(line+2,"p2align ",8)&&
                isdigit(line[10])&&line[11]=='\n'){
                    skip_next_label=1;
            }
            if (!strncmp(line + 2, "text\n", 5) ||
                !strncmp(line + 2, "section\t.text", 13) ||
                !strncmp(line + 2, "section\t__TEXT,__text", 21) ||
                !strncmp(line + 2, "section __TEXT,__text", 21)) {
                instr_ok = 1;
                continue; 
            }
            if (!strncmp(line + 2, "section\t", 8) ||
                !strncmp(line + 2, "section ", 8) ||
                !strncmp(line + 2, "bss\n", 4) ||
                !strncmp(line + 2, "data\n", 5)) {
                instr_ok = 0;
                continue;
            }
        }
        //off-flavor assembly
        if (strstr(line, ".code")) {
            if (strstr(line, ".code32")) skip_csect = use_64bit;
            if (strstr(line, ".code64")) skip_csect = !use_64bit;
        }
        if (strstr(line, ".intel_syntax")) skip_intel = 1;
        if (strstr(line, ".att_syntax")) skip_intel = 0;
        //skip ad-hoc __asm__ blocks
        if (line[0] == '#' || line[1] == '#') {
            if (strstr(line, "#APP")) skip_app = 1;
            if (strstr(line, "#NO_APP")) skip_app = 0;
        }
        if (skip_intel || skip_app || skip_csect || !instr_ok ||
            line[0] == '#' || line[0] == ' ') continue;
        //add at conditional branch
        if (line[0] == '\t') {
            if (line[1] == 'j' && line[2] != 'm' && R(100) < inst_ratio) {
                fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
                        R(MAP_SIZE));
                ins_lines++;
            }
            continue;
        } 
        //.L<whatever>:
        if(strstr(line,":")){
            if(line[0]=='.'){
                //deferred output chiefly
                if ((isdigit(line[2]) || (clang_mode && !strncmp(line + 1, "LBB", 3)))
                    && R(100) < inst_ratio) {
                        if (!skip_next_label) instrument_next = 1; else skip_next_label = 0;
                }
            }
            else{
                /* function label */
                instrument_next=1;
            }
        }
    }
    if(ins_lines){
        fputs(use_64bit?main_payload_64 : main_payload_32, outf);
    }
    if(input_file){
        fclose(inf);
    }
    fclose(outf);
    if(!be_quiet){
        if(!ins_lines){
            WARNF("no instrumentation targets found%s",pass_thru?"(pass-thru mode)":"");
        }
        else{
            OKF("Instrumented %u locations (%s-bit, %s mode, ratio %u%%).",
             ins_lines, use_64bit ? "64" : "32",
             getenv("AFL_HARDEN") ? "hardened" : 
             (sanitizer ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio);
        }
    }

}

int main(int argc,char** argv){
    s32 pid;
    u32 rand_seed;
    int status;
    u8* inst_ratio_str=getenv("AFL_INST_RATIO");
    struct timeval tv;
    struct timezone tz;
    
    clang_mode=!!getenv(CLANG_ENV_VAR);

    if(isatty(2)&&!getenv("AFL_QUIET")){
        SAYF(cCYA "afl-as " cBRI VERSION cRST " by scut");
    }
    else{
        be_quiet=1;
    }
    if(argc<2){
        SAYF("\n""helper: set AFL_INST_RATIO to a value less than 100\n");
        exit(1);
    }
    gettimeofday(&tv,&tz);
    rand_seed=tv.tv_sec^tv.tv_usec^getpid();
    srandom(rand_seed);
    edit_params(argc,argv);
    if(inst_ratio_str){
        if(sscanf(inst_ratio_str,"%u",&inst_ratio)!=1||inst_ratio>100){
            FATAL("Bad value of AFL_INST_RATIO(0~100)");
        }
    }
    if(getenv(AS_LOOP_ENV_VAR)){
        FATAL("Endless loop when calling 'as");
    }
    setenv(AS_LOOP_ENV_VAR,"1",1);
    if(getenv("AFL_USE_ASAN")||getenv("AFL_USE_MSAN")){
        sanitizer=1;
        inst_ratio/=3;
    }
    if(!just_version){
        add_instrumentation();
    }
    if(!(pid=fork())){
        execvp(as_params[0],(char**)as_params);
        FATAL("fail to exec");
    }
    if(pid<0){
        PFATAL("fork() failed");
    }
    if(waitpid(pid,&status,0)<=0){
        PFATAL("waitpid() failed");
    }
    if(!getenv("AFL_KEEP_ASSEMBLY")){
        unlink(modified_file);
    }
    exit(WEXITSTATUS(status));
    
}