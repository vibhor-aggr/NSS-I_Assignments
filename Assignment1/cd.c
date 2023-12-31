#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include "option.h"
#include "utils.h"

void check_cwd();

int main(int argc, char *argv[])
{  
  if(argc>2){
    printf("cd: too many arguments\n");
    return -1;
  }
  seteuid(getuid());
  //check_cwd();
  char* cddir=NULL;
  if(argc==1){
    cddir=getenv("HOME");
  }else{
    cddir=argv[1];
  }

  //sudo mode check permission
  bool inSudoMode=getenv("SUDO_MODE")?true:false;
  if(inSudoMode){
    const char* userName=getUsrName(getuid());
    char aclFileName[1024];
    char* aclPtr=&aclFileName[0];
    getAclFilename(argv[0], &aclPtr);
    if(!checkPermFromAcl(aclFileName, userName, 'x', false)){
      printf("cd: %s denied permission to cd to %s\n", userName, cddir);
      return 1;
    }    
  }
  else{
    //check if permission exists in acl to cd in this directory
    const char* userName=getUsrName(getuid());
    char* cddir_copy = strdup(cddir);
    char *aclPtr, *dir=cddir_copy;
    char aclFileName[1024];
    aclPtr=&aclFileName[0];
    while((dir[0]!='.' && dir[0]!='/') || dir[1]!='\0'){
      getAclFilename(dir, &aclPtr);      
      if(!checkPermFromAcl(aclFileName, userName, 'x', true)){
        printf("cd: %s denied permission to cd to %s\n", userName, cddir);
        free(cddir_copy);
        return 1;
      }
      dir=dirname(dir);
    }
    free(cddir_copy);
  }

  struct stat file_info;
  if(stat(cddir, &file_info)==0){
    seteuid(file_info.st_uid);
  }
  int ret = chdir(cddir);
  if(ret!=0){
    printf("cd: %s: %s\n",cddir, strerror(errno));
    return -1;
  }
  seteuid(getuid());
  //check_cwd();
  //printf("%s\n", pwd);
  return 0;
}

#if 0
void check_cwd()
{
  char *cwd = get_current_dir_name();      
  printf("%s\n", cwd);
  return;
}
#endif
