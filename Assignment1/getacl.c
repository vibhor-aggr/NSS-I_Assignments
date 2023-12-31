#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "utils.h"

#define BUFSIZE 10*1024

void print_getacl_usage()
{
  printf("Usage: getacl file\n");
  return;
}

int main(int argc, char* argv[]){
  if (!strcmp(argv[1], "--help")) {
    print_getacl_usage();
    return 0;
  }

  bool inSudoMode=getenv("SUDO_MODE")?true:false;
  
  seteuid(getuid());
  struct stat file_info;
  const char* userName=getUsrName(getuid());
  char aclFileName[1024];
  char* aclPtr=&aclFileName[0];
  if(stat(argv[1], &file_info)==0){
    getAclFilename(inSudoMode?argv[0]:argv[1], &aclPtr);
  }
  else{
    printf("getacl: File %s does not exist\n", argv[1]);
    print_getacl_usage();
    return 1;
  }

  if(getuid()==0){
    if(inSudoMode){
      getAclFilename(argv[1], &aclPtr);
    }
    printAcl(aclFileName);
  }
  else if(checkPermFromAcl(aclFileName, userName, inSudoMode?'x':'r', false)){
    if(inSudoMode){
      getAclFilename(argv[1], &aclPtr);
    }
    seteuid(file_info.st_uid);
    printAcl(aclFileName);
    seteuid(getuid());
  }
  else{
    printf("getacl: %s denied permission to read ACL for %s\n", getUsrName(getuid()), argv[1]);
    return 1;
  }

  return 0;
}
