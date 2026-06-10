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

void print_fget_usage()
{
  printf("Usage: fget FILENAME \n");
  return;
}

static int write_all(int fd, const char *buf, size_t size)
{
  size_t written = 0;
  while (written < size) {
    ssize_t ret = write(fd, buf + written, size - written);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (ret == 0) {
      return -1;
    }
    written += (size_t)ret;
  }
  return 0;
}

int main(int argc, char* argv[]){
  if(seteuid(getuid())==-1){
    perror("setuid failure 1");
    return 1;
  }
  if(argc!=2){
    print_fget_usage();
    return 1;
  }

  bool inSudoMode=getenv("SUDO_MODE")?true:false;

  const char* userName=getUsrName(getuid());
  struct stat file_info;
  char aclFileName[1024];
  char* aclPtr=&aclFileName[0];
  if(stat(argv[1], &file_info)==0){
    getAclFilename(inSudoMode?argv[0]:argv[1], &aclPtr);
    if(checkPermFromAcl(aclFileName, userName, inSudoMode?'x':'r', false)){
      if(seteuid(file_info.st_uid)==-1){
        perror("setuid failure 2");
        return 1;
      }
      int fd=open(argv[1], O_RDONLY);
      if(fd==-1){
        perror("fget: Error opening file");
        return 1;
      }
      //seteuid by getting info from stat of file before read
      //seteuid(file_info.st_uid);
      char buffer[1024];
      size_t bytes_to_read=1024;
      ssize_t bytes_read;
      while((bytes_read=read(fd, buffer, bytes_to_read))>0){
        if (write_all(STDOUT_FILENO, buffer, (size_t)bytes_read) != 0) {
          perror("fget: Error writing output");
          close(fd);
          return 1;
        }
      }
      if (bytes_read < 0) {
        perror("fget: Error reading file");
        close(fd);
        return 1;
      }
      //use read sys call
      close(fd);
      seteuid(getuid());
    }
    else{
      printf("fget: %s denied permission to read from %s\n", userName, argv[1]);
      return 1;
    }
  } 
  else{
    printf("fget: %s does not exist\n", argv[1]);
    return 1;
  }
  return 0;
}
