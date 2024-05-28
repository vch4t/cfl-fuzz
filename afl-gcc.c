#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static u8*  as_path;                /* Path to the AFL 'as' wrapper      */
static u8** cc_params;              /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;         /* Param count, including argv0      */
static u8   be_quiet,               /* Quiet mode                        */
            clang_mode;             /* Invoked as afl-clang*?            */

//find assembler in afl_path
static void find_as(u8* argv0){
    u8* afl_path=getenv("AFL_PATH");
    u8* slash,*tmp;
    if(afl_path){
        tmp=alloc_printf("%s/as",afl_path);
        if(!access(tmp,X_OK)){
            as_path=afl_path;
            ck_free(tmp);
            return;
        }
        ck_free(tmp);
    }
    slash=strrchr(argv0,'/');
    if(slash){
        u8 *dir;
        *slash=0;
        dir=ck_strdup(argv0);
        *slash='/';
        tmp=alloc_printf("%s/afl-as",dir);
        if(!access(tmp,X_OK)){
            as_path=dir;
            ck_free(tmp);
            return;
        }
        ck_free(tmp);
        ck_free(dir);
    }
    if(!access(AFL_PATH "/as",X_OK)){
        as_path=AFL_PATH;
        return ;
    }
    FATAL("Fail to find wrapper binary for 'as'. Please set AFL_PATH");
}

static void edit_params(u32 argc,char** argv){
    u8 fortify_set=0,asan_set=0;
    u8* name;

    cc_params=ck_alloc((argc+128)*sizeof(u8*));
    name=strrchr(argv[0],'/');
    if(!name){
        name=argv[0];
    }
    else{
        name++;
    }
    if(!strncmp(name,"afl-clang",9)){
        //may delete
        clang_mode = 1;

        setenv(CLANG_ENV_VAR, "1", 1);

        if (!strcmp(name, "afl-clang++")) {
        u8* alt_cxx = getenv("AFL_CXX");
        cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++";
        } else {
        u8* alt_cc = getenv("AFL_CC");
        cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";
        }
    }
    else{
        if(!strcmp(name,"afl-g++")){
            u8* alt_cxx=getenv("ALF_CXX");
            cc_params[0]=alt_cxx ? alt_cxx : (u8*)"g++";
        }
        //java
        else if(!strcmp(name,"afl-gcj")){
            u8* alt_cc=getenv("AFL_GCJ");
            cc_params[0]=alt_cc ? alt_cc : (u8*)"gcj";
        }
        else{
            u8* alt_cc=getenv("AFL_CC");
            cc_params[0]=alt_cc ? alt_cc : (u8*)"gcc";
        }
    }

    while(--argc){
        u8* cur= *(++argv);
        if(!strncmp(cur,"-B",2)){
            if(!be_quiet){
                WARNF("-B is set, overriding");
            }
            if(!cur[2] && argc>1){
                argc--;
                argv++;
            }
            continue;
        }
        if(!strcmp(cur,"integrated-as")) continue;
        if(!strcmp(cur,"-pipe")) continue;

        if(!strcmp(cur,"-fsanitize=address")||
           !strcmp(cur,"-fsanitize=memory")){
            asan_set=1;
        }
        if(strstr(cur,"FORTIFY_SOURCE")){
            fortify_set=1;
        }
        cc_params[cc_par_cnt++] = cur;
    }
    cc_params[cc_par_cnt++]="-B";
    cc_params[cc_par_cnt++]=as_path;
    if(clang_mode){
        cc_params[cc_par_cnt++]="-no-integrated-as";
    }
    if(getenv("AFL_HARDEN")){
        cc_params[cc_par_cnt++] = "-fstack-protector-all";
        if(!fortify_set){
            cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";
        }
    }
    if(asan_set){
        setenv("AFL_USE_ASAN","1",1);
    }
    else if(getenv("AFL_USE_ASAN")){
        if(getenv("AFL_USE_MSAN")){
            FATAL("ASAN and MSAN are mutually exclusive");
        }
        if(getenv("AFL_HARDEN")){
            FATAL("ASAN and AFL_HARDEN are mutually exclusive");
        }
        cc_params[cc_par_cnt++]="-U_FORTIFY_SOURCE";
        cc_params[cc_par_cnt++]="-fsanitize=address";
    }

    if(!getenv("AFL_DONT_OPTIMIZE")){
        cc_params[cc_par_cnt++]="-g";
        cc_params[cc_par_cnt++] = "-O3";
        cc_params[cc_par_cnt++] = "-funroll-loops";

        cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
        cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";
    }
    if (getenv("AFL_NO_BUILTIN")) {
        cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
        cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
        cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
        cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
        cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
        cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
        cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";
    }
    cc_params[cc_par_cnt]=NULL;
}


int main(int argc,char** argv){
    if(isatty(2)&&!getenv("AFL_QUIET")){
        SAYF(cCYA "afl-cc" cBRI VERSION cRST "by scut\n");
    }
    else{
        be_quiet=1;
    }
    if(argc<2){
        SAYF("\n"
            "As follow:\n"
            "  CC=%s/afl-gcc ./configure\n"
            "  CXX=%s/afl-g++ ./configure\n\n",
            BIN_PATH, BIN_PATH);
        exit(1);
    }
    find_as(argv[0]);
    edit_params(argc,argv);
    execvp(cc_params[0],(char**)cc_params);
    FATAL("Fail to execute '%s' - check the PATH",cc_params[0]);

    return 0;
}