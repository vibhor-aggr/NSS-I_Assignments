#ifndef UTILS_H
#define UTILS_H
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>

bool createAclFromStat(const char* file);
bool checkPermFromAcl(const char* aclfile, const char* userName, char perm, bool okIfNoAcl);
bool setPermInAcl(const char* aclfile, const char* userName, char perm[4]);
int printAcl(const char* aclfile);
void getAclFilename(const char* path, char** acl);
extern const char* getUsrName(uid_t uid);
void change_uid(char* path);
#endif
