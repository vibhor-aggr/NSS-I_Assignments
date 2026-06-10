#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define FAKEROOT_DIR "/fakeroot"
#define CMD_PATH_MAX 1024

static int allowed_command(const char *cmd)
{
  static const char *allowed[] = {
      "fput", "fget", "create_dir", "cd", "setacl", "getacl", NULL};

  if (cmd == NULL || strchr(cmd, '/') != NULL || strstr(cmd, "..") != NULL) {
    return 0;
  }

  for (int i = 0; allowed[i] != NULL; i++) {
    if (strcmp(cmd, allowed[i]) == 0) {
      return 1;
    }
  }
  return 0;
}

static int execute_process(const char *cmd, char *const cmd_args[])
{
  pid_t pid = fork();
  if (pid < 0) {
    perror("sudo: fork");
    return 1;
  }

  if (pid == 0) {
    execv(cmd, cmd_args);
    perror("sudo: execv");
    _exit(127);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    perror("sudo: waitpid");
    return 1;
  }

  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    fprintf(stderr, "sudo: child terminated by signal %d\n", WTERMSIG(status));
  }
  return 1;
}

int main(int argc, char *argv[])
{
  if (argc < 2) {
    fprintf(stderr, "Usage: sudo <fput|fget|create_dir|cd|setacl|getacl> [args...]\n");
    return 1;
  }

  if (!allowed_command(argv[1])) {
    fprintf(stderr, "sudo invalid command: %s\n", argv[1]);
    return 1;
  }

  char cmd_name[CMD_PATH_MAX];
  int n = snprintf(cmd_name, sizeof(cmd_name), "%s/%s", FAKEROOT_DIR, argv[1]);
  if (n < 0 || (size_t)n >= sizeof(cmd_name)) {
    fprintf(stderr, "sudo: command path too long\n");
    return 1;
  }

  if (setenv("SUDO_MODE", "1", 1) != 0) {
    perror("sudo: setenv");
    return 1;
  }

  char *cmd_args[argc];
  for (int i = 1; i < argc; i++) {
    cmd_args[i - 1] = argv[i];
  }
  cmd_args[argc - 1] = NULL;

  int ret = execute_process(cmd_name, cmd_args);
  unsetenv("SUDO_MODE");
  return ret;
}
