#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include "utils.h"

/*
Assumptions
The acl for the file or directory is stored in a separate file with .acl
file is created only using fput the very first timeAt file creation acl for file is created using dacFor subsequent fput or fget, permission is managed only using acl
fget or file is read only after creation
during fput string can either be appended to existing string or file is overwritten
fget prints the file content on the terminal
currently acl is based on user name, handling for group and other permission can be done later
*/

/*
 * Create <file>.acl for given file/directory, this is called when the file/directory is created for the first time
 * It calls stat() function call internally and populates user/group/other rwx permissions in the acl file
 */
bool createAclFromStat(const char* file)
{
    char aclFileName[1024];
    char* aclPtr=&aclFileName[0];
    getAclFilename(file, &aclPtr);

    FILE* aclFile = fopen(aclFileName, "w");
    if (aclFile == NULL) {
        perror("Error creating hidden file");
        return false;
    }

    // copy permissions from stat to hidden acl file
    struct stat statbuf;
    stat(aclFileName, &statbuf);
    mode_t fileModeRUsr = statbuf.st_mode & (S_IRUSR);
    mode_t fileModeWUsr = statbuf.st_mode & (S_IWUSR);
    mode_t fileModeXUsr = statbuf.st_mode & (S_IXUSR);
    mode_t fileModeRGrp = statbuf.st_mode & (S_IRGRP);
    mode_t fileModeWGrp = statbuf.st_mode & (S_IWGRP);
    mode_t fileModeXGrp = statbuf.st_mode & (S_IXGRP);
    mode_t fileModeROth = statbuf.st_mode & (S_IROTH);
    mode_t fileModeWOth = statbuf.st_mode & (S_IWOTH);
    mode_t fileModeXOth = statbuf.st_mode & (S_IXOTH);
    //save as default:<mode_t>

    char uPerm[4], gPerm[4], oPerm[4];
    uPerm[0]='\0';
    gPerm[0]='\0';
    oPerm[0]='\0';

    if(fileModeRUsr==S_IRUSR){
      strcat(uPerm, "r");
    }
    else{
      strcat(uPerm, "-");
    }
    if(fileModeWUsr==S_IWUSR){
      strcat(uPerm, "w");
    }
    else{
      strcat(uPerm, "-");
    }
    if(fileModeXUsr==S_IXUSR){
      strcat(uPerm, "x");
    }
    else{
      strcat(uPerm, "-");
    }

    if(fileModeRGrp==S_IRGRP){
      strcat(gPerm, "r");
    }
    else{
      strcat(gPerm, "-");
    }
    if(fileModeWGrp==S_IWGRP){
      strcat(gPerm, "w");
    }
    else{
      strcat(gPerm, "-");
    }
    if(fileModeXGrp==S_IXGRP){
      strcat(gPerm, "x");
    }
    else{
      strcat(gPerm, "-");
    }

    if(fileModeROth==S_IROTH){
      strcat(oPerm, "r");
    }
    else{
      strcat(oPerm, "-");
    }
    if(fileModeWOth==S_IWOTH){
      strcat(oPerm, "w");
    }
    else{
      strcat(oPerm, "-");
    }
    if(fileModeXOth==S_IXOTH){
      strcat(oPerm, "x");
    }
    else{
      strcat(oPerm, "-");
    }

    fprintf(aclFile, "%s::%s\n", "default:user", uPerm);
    fprintf(aclFile, "%s::%s\n", "default:group", gPerm);
    fprintf(aclFile, "%s::%s\n", "default:other", oPerm);
    fprintf(aclFile, "%s:%s:%s\n", "user", getUsrName(statbuf.st_uid), uPerm);
    // user:<user_name>:rwx
    fclose(aclFile);
    return true;
}

/* acl file format
// default:user:rwx
// default:group:rwx
// default:other:rwx
// user:<user_name>:rwx
*/

/*
 * read acl file and check for entry of 'userName', if entry is not found, return false
 * there should be only one matching entry for given userName, check if permission in that entry
 * is aligned by input 'perm' (which can be 'r', 'w' or 'x'), if yes return true else false
 */
bool checkPermFromAcl(const char* aclfile, const char* userName, char perm, bool okIfNoAcl)
{   
    uid_t call_euid=geteuid();
    struct stat file_info;
    if(stat(aclfile, &file_info)==0){
      seteuid(file_info.st_uid);
    }
    else{
      seteuid(call_euid);
      if(okIfNoAcl){
        return true;
      }
      return false;
    }
    FILE* file=fopen(aclfile, "r");
    if(file==NULL){
      seteuid(call_euid);
      if(okIfNoAcl){
        return true;
      }
      return false;
    }
    //char* line=malloc(1024*sizeof(char));
    char line[1024];
    char* lineptr=&line[0];
    size_t len=1024;
    ssize_t read;
    char* token;
    while ((read = getline(&lineptr, &len, file)) != -1){
      token=strtok(line, ":");
      if(strcmp(token, "default")==0){
          continue;
      }
      if(strcmp(token, "user")==0){
        token=strtok(NULL, ":");
        if(strcmp(token, userName)==0){
          token=strtok(NULL, ":");
          break;
        }
      }
    }
    //free(line);
    fclose(file);
    seteuid(call_euid);
    return (strchr(token, perm)!=NULL);
}

/*
 * read acl file and check for entry of 'userName', if entry is not found, create a new entry
 * there should be only one matching entry for given userName, check if permission in that entry
 * is aligned by input 'perm' (which can be 'r', 'w' or 'x'), if yes return true else false
 */
bool setPermInAcl(const char* aclfile, const char* userName, char perm[4])
{
    uid_t call_euid=geteuid();
    struct stat file_info;
    if(stat(aclfile, &file_info)==0){
      seteuid(file_info.st_uid);
    }
    else{
      seteuid(call_euid);
      return false;
    }
    FILE* file=fopen(aclfile, "r+");
    //char* line=malloc(1024*sizeof(char));
    char line[1024];
    char* lineptr=&line[0];
    size_t len=1024;
    ssize_t read;
    int pos, pos_new;
    int user_exist_acl=0;
    while ((read = getline(&lineptr, &len, file)) != -1){
      char* token=strtok(line, ":");
      if(strcmp(token, "default")==0){
        pos=ftell(file);  
        continue;
      }
      char modLine[1024];
      if(strcmp(token, "user")==0){
        sprintf(modLine, "%s:", token);
        token=strtok(NULL, ":");
        if(strcmp(token, userName)==0){
					user_exist_acl=1;
          sprintf(modLine+5, "%s:", userName);
          //token=strtok(NULL, ":");
          pos_new=ftell(file);
          fseek(file, pos, SEEK_SET);
          sprintf(modLine+5+strlen(userName)+1, "%s\n", perm);
          fputs(modLine, file);
          fseek(file, pos_new, SEEK_SET);
        }
      }
      pos=ftell(file);
    }
    //free(line);
    fclose(file);
    if(user_exist_acl==0){
      FILE* file=fopen(aclfile, "a");
      fprintf(file, "%s:%s:%s\n", "user", userName, perm);
      fclose(file);
    }
    seteuid(call_euid);
    return true;
}

int printAcl(const char* aclfile){
    uid_t call_euid=geteuid();
    struct stat file_info;
    if(stat(aclfile, &file_info)==0){
      seteuid(file_info.st_uid);
    }
    else{
      seteuid(call_euid);
      perror("Error opening file");
      return 1;
    }
    FILE* file=fopen(aclfile, "r");
    if (file == NULL) {
       seteuid(call_euid);
       perror("Error opening file");
       return 1;
    }
    //char* line=malloc(1024*sizeof(char));
    char line[1024];
    char* lineptr=&line[0];
    size_t len=1024;
    ssize_t read;
    while ((read = getline(&lineptr, &len, file)) != -1){
      printf("%s", line);
    }
    //free(line);
    fclose(file);
    seteuid(call_euid);
    return 0;
}

void getAclFilename(const char* path, char** acl){
  char* path_copy1=strdup(path);
  char* path_copy2=strdup(path);
  char* base=basename(path_copy1);
  char* dir=dirname(path_copy2);
  (*acl)[0]='\0';
  strcat(*acl, dir);
  strcat(*acl, "/.");
  strcat(*acl, base);
  strcat(*acl, ".acl");
  free(path_copy1);
  free(path_copy2);
}

void change_uid(char* path){
  struct stat file_info;
  char* path_copy=strdup(path);
  char *dir=dirname(path_copy);
  if(stat(dir, &file_info)==0){
  seteuid(file_info.st_uid);
  }
  free(path_copy);
}
