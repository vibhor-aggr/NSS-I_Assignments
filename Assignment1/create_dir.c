#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include "option.h"
#include "utils.h"

#define BUFSIZE 10*1024

void print_create_dir_usage()
{
  printf("Usage: create_dir [-p|--parents] [-v|--verbose] DIRECTORY...\n");
  return;
}

int main(int argc, char* argv[]){
  char* optStr[]={"-p","--parents","-v","--verbose","--help"};
  bool  optVal[]={false, false, false, false, false};

  if (!searchOpts(argc, argv, 5, optStr, optVal)) {
    print_create_dir_usage();
    return -1;
  }

  if (optVal[4]) {
    print_create_dir_usage();
    return 0;
  }

  bool sParent = optVal[0] || optVal[1];
  bool sVerbose = optVal[2] || optVal[3];
  seteuid(getuid());
  int noOptc = 0;
  char** noOptv = (char **)malloc(sizeof(char*)*argc);
  separateOpts(argc, argv, &noOptc, noOptv);
  if(noOptc==1){
    printf("create_dir: missing operand\n");
    print_create_dir_usage();
    free(noOptv);
    return -1;
  }

  //sudo mode check permission
  bool inSudoMode=getenv("SUDO_MODE")?true:false;
  if(inSudoMode){
    const char* userName=getUsrName(getuid());
    char aclFileName[1024];
    char* aclPtr=&aclFileName[0];
    getAclFilename(argv[0], &aclPtr);
    if(!checkPermFromAcl(aclFileName, userName, 'x', false)){
      printf("create_dir: %s denied permission to create_dir\n", userName);
      return 1;
    }    
  }

  for(int i=1;i<noOptc;i++){
    //skip if directory already exists  
    struct stat sb;
    int ret = stat(noOptv[i], &sb);
    if (!ret && S_ISDIR(sb.st_mode)) {
      continue;
    }
    if(!inSudoMode){
      //check if permission exists in acl to create this directory
      bool permGiven=true;
      bool first=true;
      const char* userName=getUsrName(getuid());
      char* dir_copy=strdup(noOptv[i]);
      char *aclPtr, *dir=dirname(dir_copy);
      char aclFileName[1024];
      aclPtr=&aclFileName[0];
      while((dir[0]!='.' && dir[0]!='/') || dir[1]!='\0'){
        getAclFilename(dir, &aclPtr);      
        if(!((!first || checkPermFromAcl(aclFileName, userName, 'w', true)) && checkPermFromAcl(aclFileName, userName, 'x', true))){
          printf("%s denied permission to create_dir %s\n", userName, noOptv[i]);
          permGiven=false;
          break;
        }
        first=false;
        dir=dirname(dir);
      }
      free(dir_copy);
      if(!permGiven){
        continue;
      }
    }
    change_uid(noOptv[i]);
    int dir=mkdir(noOptv[i],0777);
    if(dir==-1) {
      if (!sParent){
        printf("create_dir: cannot create directory '%s': %s\n",noOptv[i], strerror(errno));
        free(noOptv);  
        print_create_dir_usage();
        return -1;
      } else {
        bool isDir = false;
        struct stat sb;
        int ret = stat(noOptv[i], &sb);
        if (!ret && S_ISDIR(sb.st_mode)) {
          isDir = true;
        }
        if (errno == EEXIST && !isDir || errno != EEXIST && errno != ENOENT) {
          printf("create_dir: cannot create directory '%s': %s\n",noOptv[i], strerror(errno));
          free(noOptv);
          print_create_dir_usage();
          return -1;
        }
      }
    } else {
      if (sVerbose) {
        printf("create_dir: created directory '%s'\n", noOptv[i]);
      }
      createAclFromStat(noOptv[i]);
      continue;
    }
    char s[BUFSIZE];
    int k=0;
    for(int j=0;j<strlen(noOptv[i]);j++){
      if(noOptv[i][j]=='/'){
        if(k==0){
          s[k++]='/';
          continue;
        }
        s[k]='\0';
        change_uid(s);
        int dir=mkdir(s,0777);
        if(dir==-1 && errno != EEXIST){
          printf("create_dir: cannot create directory '%s': %s\n",noOptv[i], strerror(errno));
          free(noOptv);
          print_create_dir_usage();
          return -1;
        } else if (dir != -1){ 
          if (sVerbose) {
            printf("create_dir: created directory '%s'\n", s);
          }
          createAclFromStat(s);  
        }
        s[k++]='/';
      }else{
        s[k++]=noOptv[i][j];
      }
    }
    if(s[k-1]!='/'){
      s[k]='\0';
      change_uid(s);
      int dir=mkdir(s,0777);
      if(dir==-1 && errno != EEXIST){
        printf("create_dir: cannot create directory '%s': %s\n",noOptv[i], strerror(errno));
        free(noOptv);
        print_create_dir_usage();
        return -1;
      } else if (dir != -1){ 
        if (sVerbose) {
          printf("create_dir: created directory '%s'\n", s);
        }
        createAclFromStat(s);  
      }
    }
    seteuid(getuid());
  }
  free(noOptv);
  return 0;
}
