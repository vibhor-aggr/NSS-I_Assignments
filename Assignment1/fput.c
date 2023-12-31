#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include "utils.h"

void print_fput_usage()
{
  printf("Usage: fput FILENAME <string>\n");
  return;
}

int main(int argc, char* argv[]){
  //uid_t call_euid=geteuid();
  /*if(seteuid(1001)==-1){
    perror("setuid failure 0");
    return 1;
  }*/
  if(seteuid(getuid())==-1){
    perror("setuid failure 1");
    return 1;
  }
  if(argc!=3){
    print_fput_usage();
    return 1;
  }

  bool inSudoMode=getenv("SUDO_MODE")?true:false;

  const char* userName=getUsrName(getuid());
  struct stat file_info;
  char aclFileName[1024];
  char* aclPtr=&aclFileName[0];
  if(stat(argv[1], &file_info)==0){
    getAclFilename(inSudoMode?argv[0]:argv[1], &aclPtr);
    if(checkPermFromAcl(aclFileName, userName, inSudoMode?'x':'w', false)){
      //seteuid by getting info from stat of file before write
      /*if(seteuid(call_euid)==-1){
        perror("setuid failure 2");
        return 1;
      }*/
      if(seteuid(file_info.st_uid)==-1){
        perror("setuid failure 2");
        return 1;
      }
      int fd=open(argv[1], O_APPEND | O_RDWR);
      if(fd==-1){
        perror("fput: Error opening file");
        return 1;
      }
      size_t size=strlen(argv[2]);
      //use write sys call
      while(write(fd, argv[2], size)!=size);
      while(write(fd, "\n", 1)!=1);
      close(fd);
      seteuid(getuid());
    }
    else{
      printf("fput: %s denied permission to write to %s\n", userName, argv[1]);
      return 1;
    }
  }
  else{
    if(inSudoMode){
      getAclFilename(argv[0], &aclPtr);      
      if(!checkPermFromAcl(aclFileName, userName, 'x', false)){    
        printf("fput: %s denied permission to write to %s\n", userName, argv[1]);
        return 1;
      }  
      change_uid(argv[1]);
    }
    else{      
      struct stat file_info;
      char aclFileName[1024];
      char* aclPtr=&aclFileName[0];
      char* dir_copy=strdup(argv[1]);
      char* pdir=dirname(dir_copy);
      if(stat(pdir, &file_info)==0){
        getAclFilename(pdir, &aclPtr);
        if(checkPermFromAcl(aclFileName, userName, 'w', false)){
          if(seteuid(file_info.st_uid)==-1){
            perror("setuid failure");
            return 1;
          }
        }
        else{
          printf("fput: %s denied permission to write to %s\n", userName, argv[1]);
          return 1;
        }
      }
    }
    int fd=open(argv[1], O_CREAT | O_RDWR, 0644);
    if(fd==-1){
      perror("fput: Error opening file");
      return 1;
    }
    createAclFromStat(argv[1]);
    //seteuid by getting info from stat of file before write
    //seteuid(file_info.st_uid);
    size_t size=strlen(argv[2]);
    //use write sys call
    while(write(fd, argv[2], size)!=size);
    while(write(fd, "\n", 1)!=1);
    close(fd);
    //seteuid(getuid());
  }
  return 0;
}
