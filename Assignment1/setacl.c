#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include "option.h"
#include "utils.h"

void print_setacl_usage()
{
  printf("Usage: setacl [-m|--modify|-x|--remove] acl_spec file ...\n");
  return;
}

int main(int argc, char* argv[]){
  //sleep(60);
  char* optStr[]={"-m","--modify","-x","--remove","--help"};
  bool  optVal[]={false, false, false, false, false};

  if (!searchOpts(argc, argv, 5, optStr, optVal)) {
    print_setacl_usage();
    return -1;
  }

  if (optVal[4]) {
    print_setacl_usage();
    return 0;
  }

  bool sModify = optVal[0] || optVal[1];
  bool sRemove = optVal[2] || optVal[3];
  
  char* token;
  token=strtok(argv[2], ":");
  if(strcmp(token, "u")){
    printf("setacl: Wrong modifier %s\n", token);
    print_setacl_usage();
    return 1;
  }
  seteuid(getuid());
  token=strtok(NULL, ":");
  const char* userName=token;
  struct passwd *user_info = getpwnam(userName);
  if(user_info==NULL){
    printf("setacl: User %s does not exist\n", userName);
    print_setacl_usage();
    return 1;
  }
  if(sModify){
    token=strtok(NULL, ":");
    if(strlen(token)!=3){
      printf("setacl: Wrong modifier %s\n", token);
      print_setacl_usage();
      return 1;
    }
    if(token[0]!='r' && token[0]!='-' || token[1]!='w' && token[1]!='-' || token[2]!='x' && token[2]!='-'){
      printf("setacl: Wrong modifier %s\n", token);
      print_setacl_usage();
      return 1;
    }
  }
  else{
    token="---";
  }

  bool inSudoMode=getenv("SUDO_MODE")?true:false;
  
  struct stat file_info;
  char aclFileName[1024];
  char* aclPtr=&aclFileName[0];
  if(stat(argv[3], &file_info)==0){
    getAclFilename(inSudoMode?argv[0]:argv[3], &aclPtr);
  }
  else{
    printf("setacl: File %s does not exist\n", argv[3]);
    print_setacl_usage();
    return 1;
  }

  if(getuid()==0){
    if(inSudoMode){
      getAclFilename(argv[3], &aclPtr);
    }
    setPermInAcl(aclFileName, userName, token);
  }
  else if(checkPermFromAcl(aclFileName, getUsrName(getuid()), inSudoMode?'x':'w', false)){
    if(inSudoMode){
      getAclFilename(argv[3], &aclPtr);
    }
    seteuid(file_info.st_uid);
    setPermInAcl(aclFileName, userName, token);
    seteuid(getuid());
  }
  else{
    printf("setacl: %s denied permission to set ACL for %s\n", getUsrName(getuid()), argv[3]);
    return 1;
  }

  return 0;
}
