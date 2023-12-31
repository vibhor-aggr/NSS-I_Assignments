//use fork and exec to execute fput, fget
//either check perm in acl here or inside the called process like fput
//can setenv to let fput know that it is called from sudo
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include "option.h"

void* sys_call(void* args){
  //printf("system() args: %s\n", (char*)args);
  system((char*)args);
}

void execute_process(char* cmd, char* cmdArgs[]){
  
  //printf("process command = %s %s\n", cmd, cmdArgs);

  pid_t pid;
  pid=fork();
  if(pid==0){
    //printf("Inside child process\n");
    execv(cmd, cmdArgs);
  }
  else if(pid>0){
    //printf("Inside parent process\n");
    wait(0);
    return;
  }
}

int main(int argc, char* argv[])
{
  if(!(!strcmp(argv[1], "fput") || !strcmp(argv[1], "fget") || !strcmp(argv[1], "create_dir") ||
       !strcmp(argv[1], "cd") || !strcmp(argv[1], "setacl") || !strcmp(argv[1], "getacl"))){
    printf("sudo invalid command: %s\n", argv[1]);
    return 1;
  }
  char cmdName[1024];
  //char* cdir = getenv("PWD");
  char* cdir = "/fakeroot";
  sprintf(cmdName, "%s/%s", cdir, argv[1]);
#if 0  
  char cmdArgs[1024*8];
  cmdArgs[0]='\0';
  for(int i=2; i<argc; i++){
    strcat(cmdArgs, " \"");
    strcat(cmdArgs, argv[i]);
    strcat(cmdArgs, "\" ");
  }
#endif
  setenv("SUDO_MODE", "1", 1);
  char* cmdArgs[argc];
  cmdArgs[argc-1]='\0';
  for(int i=1; i<argc;i++){
    cmdArgs[i-1]=argv[i];
  }
  execute_process(cmdName, cmdArgs);
  unsetenv("SUDO_MODE");

  return 0;
}
