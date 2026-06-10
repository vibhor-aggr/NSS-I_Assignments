#define _GNU_SOURCE
#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

#define ACL_PATH_MAX 1024
#define ACL_LINE_MAX 1024

static void build_perm(mode_t mode, mode_t r, mode_t w, mode_t x, char out[4])
{
  out[0] = (mode & r) ? 'r' : '-';
  out[1] = (mode & w) ? 'w' : '-';
  out[2] = (mode & x) ? 'x' : '-';
  out[3] = '\0';
}

static int valid_perm_string(const char *perm)
{
  return perm != NULL && strlen(perm) >= 3 &&
         (perm[0] == 'r' || perm[0] == '-') &&
         (perm[1] == 'w' || perm[1] == '-') &&
         (perm[2] == 'x' || perm[2] == '-');
}

static int line_has_perm(const char *line, const char *user_name, char perm)
{
  char copy[ACL_LINE_MAX];
  char *kind;
  char *name;
  char *mode;

  if (line == NULL || user_name == NULL) {
    return -1;
  }

  if (snprintf(copy, sizeof(copy), "%s", line) >= (int)sizeof(copy)) {
    return -1;
  }

  kind = strtok(copy, ":\n");
  if (kind == NULL || strcmp(kind, "default") == 0) {
    return 0;
  }
  if (strcmp(kind, "user") != 0) {
    return 0;
  }

  name = strtok(NULL, ":\n");
  mode = strtok(NULL, ":\n");
  if (name == NULL || mode == NULL || !valid_perm_string(mode)) {
    return -1;
  }
  if (strcmp(name, user_name) != 0) {
    return 0;
  }
  return strchr(mode, perm) != NULL;
}

bool createAclFromStat(const char *file)
{
  char acl_file_name[ACL_PATH_MAX];
  char *acl_ptr = acl_file_name;
  struct stat statbuf;
  FILE *acl_file;
  char u_perm[4], g_perm[4], o_perm[4];
  const char *owner_name;

  if (file == NULL || stat(file, &statbuf) != 0) {
    return false;
  }

  getAclFilename(file, &acl_ptr);
  if (acl_file_name[0] == '\0') {
    return false;
  }

  acl_file = fopen(acl_file_name, "w");
  if (acl_file == NULL) {
    perror("Error creating hidden file");
    return false;
  }

  build_perm(statbuf.st_mode, S_IRUSR, S_IWUSR, S_IXUSR, u_perm);
  build_perm(statbuf.st_mode, S_IRGRP, S_IWGRP, S_IXGRP, g_perm);
  build_perm(statbuf.st_mode, S_IROTH, S_IWOTH, S_IXOTH, o_perm);

  owner_name = getUsrName(statbuf.st_uid);
  if (owner_name == NULL) {
    fclose(acl_file);
    return false;
  }

  fprintf(acl_file, "default:user:%s\n", u_perm);
  fprintf(acl_file, "default:group:%s\n", g_perm);
  fprintf(acl_file, "default:other:%s\n", o_perm);
  fprintf(acl_file, "user:%s:%s\n", owner_name, u_perm);
  fclose(acl_file);
  return true;
}

bool checkPermFromAcl(const char *aclfile, const char *userName, char perm, bool okIfNoAcl)
{
  uid_t call_euid = geteuid();
  struct stat file_info;
  FILE *file;
  char line[ACL_LINE_MAX];

  if (aclfile == NULL || aclfile[0] == '\0' || userName == NULL) {
    return false;
  }

  if (stat(aclfile, &file_info) != 0) {
    if (okIfNoAcl) {
      return true;
    }
    return false;
  }

  if (seteuid(file_info.st_uid) == -1) {
    return false;
  }

  file = fopen(aclfile, "r");
  if (file == NULL) {
    seteuid(call_euid);
    return okIfNoAcl;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    int result = line_has_perm(line, userName, perm);
    if (result < 0) {
      fclose(file);
      seteuid(call_euid);
      return false;
    }
    if (result > 0) {
      fclose(file);
      seteuid(call_euid);
      return true;
    }
  }

  fclose(file);
  seteuid(call_euid);
  return false;
}

bool setPermInAcl(const char *aclfile, const char *userName, char perm[4])
{
  uid_t call_euid = geteuid();
  struct stat file_info;
  FILE *in;
  FILE *out;
  char tmp_path[ACL_PATH_MAX];
  char line[ACL_LINE_MAX];
  int found = 0;

  if (aclfile == NULL || aclfile[0] == '\0' || userName == NULL || !valid_perm_string(perm)) {
    return false;
  }

  if (stat(aclfile, &file_info) != 0) {
    return false;
  }
  if (seteuid(file_info.st_uid) == -1) {
    return false;
  }

  if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", aclfile, (long)getpid()) >=
      (int)sizeof(tmp_path)) {
    seteuid(call_euid);
    return false;
  }

  in = fopen(aclfile, "r");
  out = fopen(tmp_path, "w");
  if (in == NULL || out == NULL) {
    if (in != NULL) {
      fclose(in);
    }
    if (out != NULL) {
      fclose(out);
      unlink(tmp_path);
    }
    seteuid(call_euid);
    return false;
  }

  while (fgets(line, sizeof(line), in) != NULL) {
    char copy[ACL_LINE_MAX];
    char *kind;
    char *name;

    if (snprintf(copy, sizeof(copy), "%s", line) >= (int)sizeof(copy)) {
      fclose(in);
      fclose(out);
      unlink(tmp_path);
      seteuid(call_euid);
      return false;
    }

    kind = strtok(copy, ":\n");
    name = strtok(NULL, ":\n");
    if (kind != NULL && name != NULL && strcmp(kind, "user") == 0 &&
        strcmp(name, userName) == 0) {
      fprintf(out, "user:%s:%s\n", userName, perm);
      found = 1;
    } else {
      fputs(line, out);
    }
  }

  if (!found) {
    fprintf(out, "user:%s:%s\n", userName, perm);
  }

  fclose(in);
  if (fclose(out) != 0 || rename(tmp_path, aclfile) != 0) {
    unlink(tmp_path);
    seteuid(call_euid);
    return false;
  }

  seteuid(call_euid);
  return true;
}

int printAcl(const char *aclfile)
{
  uid_t call_euid = geteuid();
  struct stat file_info;
  FILE *file;
  char line[ACL_LINE_MAX];

  if (aclfile == NULL || aclfile[0] == '\0' || stat(aclfile, &file_info) != 0) {
    perror("Error opening file");
    return 1;
  }

  if (seteuid(file_info.st_uid) == -1) {
    perror("seteuid");
    return 1;
  }

  file = fopen(aclfile, "r");
  if (file == NULL) {
    seteuid(call_euid);
    perror("Error opening file");
    return 1;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    fputs(line, stdout);
  }

  fclose(file);
  seteuid(call_euid);
  return 0;
}

void getAclFilename(const char *path, char **acl)
{
  char *path_copy1;
  char *path_copy2;
  char *base;
  char *dir;
  int n;

  if (acl == NULL || *acl == NULL) {
    return;
  }
  (*acl)[0] = '\0';
  if (path == NULL) {
    return;
  }

  path_copy1 = strdup(path);
  path_copy2 = strdup(path);
  if (path_copy1 == NULL || path_copy2 == NULL) {
    free(path_copy1);
    free(path_copy2);
    return;
  }

  base = basename(path_copy1);
  dir = dirname(path_copy2);
  n = snprintf(*acl, ACL_PATH_MAX, "%s/.%s.acl", dir, base);
  if (n < 0 || n >= ACL_PATH_MAX) {
    (*acl)[0] = '\0';
  }

  free(path_copy1);
  free(path_copy2);
}

void change_uid(char *path)
{
  struct stat file_info;
  char *path_copy;
  char *dir;

  if (path == NULL) {
    return;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return;
  }

  dir = dirname(path_copy);
  if (stat(dir, &file_info) == 0) {
    seteuid(file_info.st_uid);
  }
  free(path_copy);
}
