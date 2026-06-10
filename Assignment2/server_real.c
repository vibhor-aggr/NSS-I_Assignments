#define _GNU_SOURCE
#include "a2_common.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_USERS 32
#define MAX_CLIENTS 32
#define MAX_GROUPS 32
#define MAX_GROUP_MEMBERS 32
#define MAX_REPLAY 128
#define TICKET_TTL 3600

typedef struct {
  char name[32];
  char password[128];
  char root[256];
  unsigned char long_key[A2_KEY_LEN];
} user_record_t;

typedef struct {
  int active;
  int fd;
  char user[32];
  unsigned char session[A2_KEY_LEN];
  char public_key[2048];
} client_t;

typedef struct {
  int used;
  int id;
  char name[64];
  char owner[32];
  char members[MAX_GROUP_MEMBERS][32];
  int member_count;
  char invites[MAX_GROUP_MEMBERS][32];
  int invite_count;
  unsigned char key[A2_KEY_LEN];
  int has_key;
} group_t;

typedef struct {
  char value[128];
  time_t seen;
} replay_entry_t;

typedef struct {
  char kdc_port[16];
  char chat_port[16];
  char users_path[256];
  char root_dir[256];
  char bind_host[64];
} server_config_t;

static user_record_t users[MAX_USERS];
static int user_count = 0;
static client_t clients[MAX_CLIENTS];
static group_t groups[MAX_GROUPS];
static replay_entry_t replays[MAX_REPLAY];
static int replay_next = 0;
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned char ticket_key[A2_KEY_LEN];
static server_config_t cfg = {
    .kdc_port = "9000",
    .chat_port = "9001",
    .users_path = "users.db",
    .root_dir = "files",
    .bind_host = "0.0.0.0",
};

static void usage(const char *argv0)
{
  fprintf(stderr,
          "Usage: %s [--bind HOST] [--kdc-port PORT] [--chat-port PORT] "
          "[--users users.db] [--root files]\n",
          argv0);
}

static int parse_args(int argc, char **argv)
{
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
      snprintf(cfg.bind_host, sizeof(cfg.bind_host), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--kdc-port") == 0 && i + 1 < argc) {
      snprintf(cfg.kdc_port, sizeof(cfg.kdc_port), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--chat-port") == 0 && i + 1 < argc) {
      snprintf(cfg.chat_port, sizeof(cfg.chat_port), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--users") == 0 && i + 1 < argc) {
      snprintf(cfg.users_path, sizeof(cfg.users_path), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
      snprintf(cfg.root_dir, sizeof(cfg.root_dir), "%s", argv[++i]);
    } else {
      usage(argv[0]);
      return -1;
    }
  }
  return 0;
}

static int find_user(const char *name)
{
  for (int i = 0; i < user_count; i++) {
    if (strcmp(users[i].name, name) == 0) {
      return i;
    }
  }
  return -1;
}

static int load_default_users(void)
{
  const char *defaults[][3] = {
      {"alice", "alicepass", "files/alice"},
      {"bob", "bobpass", "files/bob"},
      {"carol", "carolpass", "files/carol"},
  };
  user_count = 3;
  for (int i = 0; i < user_count; i++) {
    snprintf(users[i].name, sizeof(users[i].name), "%s", defaults[i][0]);
    snprintf(users[i].password, sizeof(users[i].password), "%s", defaults[i][1]);
    snprintf(users[i].root, sizeof(users[i].root), "%s", defaults[i][2]);
    if (derive_long_term_key(users[i].name, users[i].password, users[i].long_key) != 0) {
      return -1;
    }
    ensure_dir(cfg.root_dir);
    ensure_dir(users[i].root);
  }
  return 0;
}

static int load_users(void)
{
  FILE *f = fopen(cfg.users_path, "r");
  char line[512];
  if (f == NULL) {
    fprintf(stderr, "server: %s not found; using demo users alice/bob/carol\n", cfg.users_path);
    return load_default_users();
  }

  while (fgets(line, sizeof(line), f) != NULL && user_count < MAX_USERS) {
    char *name;
    char *password;
    char *root;
    trim_newline(line);
    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }
    name = strtok(line, ":");
    password = strtok(NULL, ":");
    root = strtok(NULL, ":");
    if (name == NULL || password == NULL || root == NULL) {
      continue;
    }
    snprintf(users[user_count].name, sizeof(users[user_count].name), "%s", name);
    snprintf(users[user_count].password, sizeof(users[user_count].password), "%s", password);
    snprintf(users[user_count].root, sizeof(users[user_count].root), "%s", root);
    if (derive_long_term_key(name, password, users[user_count].long_key) != 0) {
      fclose(f);
      return -1;
    }
    ensure_dir(root);
    user_count++;
  }
  fclose(f);
  return user_count > 0 ? 0 : load_default_users();
}

static int replay_seen_or_add(const char *nonce)
{
  time_t now = time(NULL);
  int seen = 0;
  pthread_mutex_lock(&state_lock);
  for (int i = 0; i < MAX_REPLAY; i++) {
    if (replays[i].value[0] != '\0' && strcmp(replays[i].value, nonce) == 0) {
      seen = 1;
      break;
    }
  }
  if (!seen) {
    snprintf(replays[replay_next].value, sizeof(replays[replay_next].value), "%s", nonce);
    replays[replay_next].seen = now;
    replay_next = (replay_next + 1) % MAX_REPLAY;
  }
  pthread_mutex_unlock(&state_lock);
  return seen;
}

static client_t *find_client_locked(const char *user)
{
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].active && strcmp(clients[i].user, user) == 0) {
      return &clients[i];
    }
  }
  return NULL;
}

static void send_to_user(const char *user, const char *msg)
{
  pthread_mutex_lock(&state_lock);
  client_t *c = find_client_locked(user);
  if (c != NULL) {
    send_all(c->fd, msg);
  }
  pthread_mutex_unlock(&state_lock);
}

static void broadcast_message(const char *from, const char *msg)
{
  pthread_mutex_lock(&state_lock);
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].active) {
      send_fmt(clients[i].fd, "MSG all %s %s\n", from, msg);
    }
  }
  pthread_mutex_unlock(&state_lock);
}

static int client_slot_add(int fd, const char *user, const unsigned char session[A2_KEY_LEN])
{
  int slot = -1;
  pthread_mutex_lock(&state_lock);
  if (find_client_locked(user) != NULL) {
    pthread_mutex_unlock(&state_lock);
    return -1;
  }
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (!clients[i].active) {
      slot = i;
      clients[i].active = 1;
      clients[i].fd = fd;
      snprintf(clients[i].user, sizeof(clients[i].user), "%s", user);
      memcpy(clients[i].session, session, A2_KEY_LEN);
      clients[i].public_key[0] = '\0';
      break;
    }
  }
  pthread_mutex_unlock(&state_lock);
  return slot;
}

static void client_slot_remove(int fd)
{
  pthread_mutex_lock(&state_lock);
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].active && clients[i].fd == fd) {
      memset(&clients[i], 0, sizeof(clients[i]));
      break;
    }
  }
  pthread_mutex_unlock(&state_lock);
}

static int group_has_member(const group_t *g, const char *user)
{
  for (int i = 0; i < g->member_count; i++) {
    if (strcmp(g->members[i], user) == 0) {
      return 1;
    }
  }
  return 0;
}

static int group_has_invite(const group_t *g, const char *user)
{
  for (int i = 0; i < g->invite_count; i++) {
    if (strcmp(g->invites[i], user) == 0) {
      return 1;
    }
  }
  return 0;
}

static group_t *find_group_locked(int id)
{
  for (int i = 0; i < MAX_GROUPS; i++) {
    if (groups[i].used && groups[i].id == id) {
      return &groups[i];
    }
  }
  return NULL;
}

static void derive_ticket_key(void)
{
  sha256_bytes((const unsigned char *)"nss-assignment2-chat-ticket-key",
               strlen("nss-assignment2-chat-ticket-key"), ticket_key);
}

static int decrypt_ticket(const char *iv_hex, const char *tag_hex, const char *ct_hex,
                          char *user, size_t user_len,
                          unsigned char session[A2_KEY_LEN])
{
  unsigned char iv[A2_GCM_IV_LEN], tag[A2_GCM_TAG_LEN];
  unsigned char ciphertext[2048], plaintext[2048];
  int ct_len, pt_len;
  char *tok_user;
  char *tok_expiry;
  char *tok_session;
  long expiry;

  if (hex_decode(iv_hex, iv, sizeof(iv)) != A2_GCM_IV_LEN ||
      hex_decode(tag_hex, tag, sizeof(tag)) != A2_GCM_TAG_LEN ||
      (ct_len = hex_decode(ct_hex, ciphertext, sizeof(ciphertext))) <= 0) {
    return -1;
  }

  pt_len = aes_256_gcm_decrypt(ticket_key, iv, tag, ciphertext, ct_len,
                               NULL, 0, plaintext);
  if (pt_len < 0 || pt_len >= (int)sizeof(plaintext)) {
    return -1;
  }
  plaintext[pt_len] = '\0';
  tok_user = strtok((char *)plaintext, "|");
  tok_expiry = strtok(NULL, "|");
  tok_session = strtok(NULL, "|");
  if (tok_user == NULL || tok_expiry == NULL || tok_session == NULL) {
    return -1;
  }
  expiry = strtol(tok_expiry, NULL, 10);
  if (expiry < time(NULL)) {
    return -1;
  }
  if (hex_decode(tok_session, session, A2_KEY_LEN) != A2_KEY_LEN) {
    return -1;
  }
  snprintf(user, user_len, "%s", tok_user);
  return 0;
}

static void *kdc_client_thread(void *arg)
{
  int fd = *(int *)arg;
  free(arg);
  char line[A2_LINE_MAX];
  char *cmd, *user, *nonce, *timestamp_s, *hmac_hex;
  unsigned char expected[A2_HMAC_LEN], got[A2_HMAC_LEN];
  char hmac_input[512];
  int user_idx;

  if (recv_line(fd, line, sizeof(line)) <= 0) {
    close(fd);
    return NULL;
  }
  trim_newline(line);
  cmd = strtok(line, " ");
  user = strtok(NULL, " ");
  nonce = strtok(NULL, " ");
  timestamp_s = strtok(NULL, " ");
  hmac_hex = strtok(NULL, " ");
  if (cmd == NULL || strcmp(cmd, "AUTH") != 0 || user == NULL || nonce == NULL ||
      timestamp_s == NULL || hmac_hex == NULL) {
    send_all(fd, "ERR bad-auth-format\n");
    close(fd);
    return NULL;
  }

  user_idx = find_user(user);
  if (user_idx < 0 || replay_seen_or_add(nonce)) {
    send_all(fd, "ERR authentication-failed\n");
    close(fd);
    return NULL;
  }

  long ts = strtol(timestamp_s, NULL, 10);
  if (labs(time(NULL) - ts) > 300) {
    send_all(fd, "ERR stale-authenticator\n");
    close(fd);
    return NULL;
  }

  snprintf(hmac_input, sizeof(hmac_input), "AUTH|%s|%s|%s", user, nonce, timestamp_s);
  if (hmac_sha256(users[user_idx].long_key, A2_KEY_LEN,
                  (const unsigned char *)hmac_input, strlen(hmac_input), expected) != 0 ||
      hex_decode(hmac_hex, got, sizeof(got)) != A2_HMAC_LEN ||
      CRYPTO_memcmp(expected, got, A2_HMAC_LEN) != 0) {
    send_all(fd, "ERR authentication-failed\n");
    close(fd);
    return NULL;
  }

  unsigned char session[A2_KEY_LEN];
  char session_hex[A2_KEY_LEN * 2 + 1];
  char ticket_plain[512];
  char payload[2048];
  unsigned char ticket_iv[A2_GCM_IV_LEN], ticket_tag[A2_GCM_TAG_LEN];
  unsigned char payload_iv[A2_GCM_IV_LEN], payload_tag[A2_GCM_TAG_LEN];
  unsigned char ticket_ct[512], payload_ct[3072];
  char ticket_iv_hex[sizeof(ticket_iv) * 2 + 1], ticket_tag_hex[sizeof(ticket_tag) * 2 + 1];
  char ticket_ct_hex[sizeof(ticket_ct) * 2 + 1], payload_iv_hex[sizeof(payload_iv) * 2 + 1];
  char payload_tag_hex[sizeof(payload_tag) * 2 + 1], payload_ct_hex[sizeof(payload_ct) * 2 + 1];
  long expiry = time(NULL) + TICKET_TTL;
  int ticket_len, payload_len;

  if (random_bytes(session, sizeof(session)) != 0 ||
      hex_encode(session, sizeof(session), session_hex, sizeof(session_hex)) != 0) {
    send_all(fd, "ERR internal\n");
    close(fd);
    return NULL;
  }
  snprintf(ticket_plain, sizeof(ticket_plain), "%s|%ld|%s", user, expiry, session_hex);
  ticket_len = aes_256_gcm_encrypt(ticket_key, (const unsigned char *)ticket_plain,
                                   (int)strlen(ticket_plain), NULL, 0,
                                   ticket_iv, ticket_tag, ticket_ct);
  if (ticket_len < 0) {
    send_all(fd, "ERR internal\n");
    close(fd);
    return NULL;
  }
  hex_encode(ticket_iv, sizeof(ticket_iv), ticket_iv_hex, sizeof(ticket_iv_hex));
  hex_encode(ticket_tag, sizeof(ticket_tag), ticket_tag_hex, sizeof(ticket_tag_hex));
  hex_encode(ticket_ct, (size_t)ticket_len, ticket_ct_hex, sizeof(ticket_ct_hex));
  snprintf(payload, sizeof(payload), "%s %ld %s %s %s",
           session_hex, expiry, ticket_iv_hex, ticket_tag_hex, ticket_ct_hex);
  payload_len = aes_256_gcm_encrypt(users[user_idx].long_key,
                                    (const unsigned char *)payload, (int)strlen(payload),
                                    NULL, 0, payload_iv, payload_tag, payload_ct);
  if (payload_len < 0) {
    send_all(fd, "ERR internal\n");
    close(fd);
    return NULL;
  }
  hex_encode(payload_iv, sizeof(payload_iv), payload_iv_hex, sizeof(payload_iv_hex));
  hex_encode(payload_tag, sizeof(payload_tag), payload_tag_hex, sizeof(payload_tag_hex));
  hex_encode(payload_ct, (size_t)payload_len, payload_ct_hex, sizeof(payload_ct_hex));
  send_fmt(fd, "OK %s %s %s\n", payload_iv_hex, payload_tag_hex, payload_ct_hex);
  close(fd);
  return NULL;
}

static void *kdc_accept_thread(void *arg)
{
  (void)arg;
  int listener = tcp_listen(cfg.bind_host, cfg.kdc_port, 32);
  if (listener < 0) {
    perror("server: KDC listen");
    exit(1);
  }
  fprintf(stderr, "server: KDC listening on %s:%s\n", cfg.bind_host, cfg.kdc_port);
  for (;;) {
    int fd = accept(listener, NULL, NULL);
    if (fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("server: KDC accept");
      continue;
    }
    int *arg_fd = malloc(sizeof(int));
    pthread_t tid;
    if (arg_fd == NULL) {
      close(fd);
      continue;
    }
    *arg_fd = fd;
    pthread_create(&tid, NULL, kdc_client_thread, arg_fd);
    pthread_detach(tid);
  }
}

static int authenticate_chat(int fd, char *user, size_t user_len,
                             unsigned char session[A2_KEY_LEN])
{
  char line[A2_LINE_MAX];
  char *cmd, *iv_hex, *tag_hex, *ct_hex, *nonce, *hmac_hex;
  unsigned char expected[A2_HMAC_LEN], got[A2_HMAC_LEN];
  char hmac_input[512];

  if (recv_line(fd, line, sizeof(line)) <= 0) {
    return -1;
  }
  trim_newline(line);
  cmd = strtok(line, " ");
  iv_hex = strtok(NULL, " ");
  tag_hex = strtok(NULL, " ");
  ct_hex = strtok(NULL, " ");
  nonce = strtok(NULL, " ");
  hmac_hex = strtok(NULL, " ");
  if (cmd == NULL || strcmp(cmd, "TICKET") != 0 || iv_hex == NULL || tag_hex == NULL ||
      ct_hex == NULL || nonce == NULL || hmac_hex == NULL) {
    return -1;
  }
  if (replay_seen_or_add(nonce) || decrypt_ticket(iv_hex, tag_hex, ct_hex, user, user_len, session) != 0) {
    return -1;
  }
  snprintf(hmac_input, sizeof(hmac_input), "CHAT|%s|%s", user, nonce);
  if (hmac_sha256(session, A2_KEY_LEN, (const unsigned char *)hmac_input,
                  strlen(hmac_input), expected) != 0 ||
      hex_decode(hmac_hex, got, sizeof(got)) != A2_HMAC_LEN ||
      CRYPTO_memcmp(expected, got, A2_HMAC_LEN) != 0) {
    return -1;
  }
  return 0;
}

static int acl_allows_read(const char *path, const char *requester)
{
  char copy1[512], copy2[512], acl_path[1024];
  char *base;
  char *dir;
  FILE *f;
  char line[512];

  snprintf(copy1, sizeof(copy1), "%s", path);
  snprintf(copy2, sizeof(copy2), "%s", path);
  base = basename(copy1);
  dir = dirname(copy2);
  snprintf(acl_path, sizeof(acl_path), "%s/.%s.acl", dir, base);
  f = fopen(acl_path, "r");
  if (f == NULL) {
    return 0;
  }
  while (fgets(line, sizeof(line), f) != NULL) {
    char *kind;
    char *name;
    char *perm;
    trim_newline(line);
    kind = strtok(line, ":");
    name = strtok(NULL, ":");
    perm = strtok(NULL, ":");
    if (kind == NULL || name == NULL || perm == NULL) {
      continue;
    }
    if (strcmp(kind, "user") == 0 && strcmp(name, requester) == 0 && strchr(perm, 'r') != NULL) {
      fclose(f);
      return 1;
    }
    if (strcmp(kind, "default") == 0 && strcmp(name, "other") == 0 && strchr(perm, 'r') != NULL) {
      fclose(f);
      return 1;
    }
  }
  fclose(f);
  return 0;
}

static int can_read_user_file(const char *requester, const char *owner, const char *filename,
                              char *path, size_t path_len)
{
  int idx = find_user(owner);
  if (idx < 0 || strchr(filename, '/') != NULL || strstr(filename, "..") != NULL) {
    return 0;
  }
  if (snprintf(path, path_len, "%s/%s", users[idx].root, filename) >= (int)path_len) {
    return 0;
  }
  if (access(path, R_OK) != 0) {
    return 0;
  }
  if (strcmp(requester, owner) == 0) {
    return 1;
  }
  return acl_allows_read(path, requester);
}

static void handle_who(int fd)
{
  send_all(fd, "USERS");
  pthread_mutex_lock(&state_lock);
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].active) {
      send_fmt(fd, " %s", clients[i].user);
    }
  }
  pthread_mutex_unlock(&state_lock);
  send_all(fd, "\n");
}

static void handle_create_group(int fd, const char *user, const char *name)
{
  int id = -1;
  pthread_mutex_lock(&state_lock);
  for (int i = 0; i < MAX_GROUPS; i++) {
    if (!groups[i].used) {
      groups[i].used = 1;
      groups[i].id = i + 1;
      snprintf(groups[i].name, sizeof(groups[i].name), "%s", name != NULL ? name : "group");
      snprintf(groups[i].owner, sizeof(groups[i].owner), "%s", user);
      snprintf(groups[i].members[0], sizeof(groups[i].members[0]), "%s", user);
      groups[i].member_count = 1;
      groups[i].invite_count = 0;
      groups[i].has_key = 0;
      id = groups[i].id;
      break;
    }
  }
  pthread_mutex_unlock(&state_lock);
  if (id < 0) {
    send_all(fd, "ERR no-group-slots\n");
  } else {
    send_fmt(fd, "GROUP_CREATED %d %s\n", id, name != NULL ? name : "group");
  }
}

static void handle_group_invite(int fd, const char *from, int group_id, const char *to)
{
  int ok = 0;
  pthread_mutex_lock(&state_lock);
  group_t *g = find_group_locked(group_id);
  if (g != NULL && group_has_member(g, from) && !group_has_member(g, to) &&
      !group_has_invite(g, to) && g->invite_count < MAX_GROUP_MEMBERS) {
    snprintf(g->invites[g->invite_count++], sizeof(g->invites[0]), "%s", to);
    ok = 1;
  }
  pthread_mutex_unlock(&state_lock);
  if (!ok) {
    send_all(fd, "ERR invite-failed\n");
    return;
  }
  send_fmt(fd, "INVITE_SENT %d %s\n", group_id, to);
  char msg[A2_LINE_MAX];
  snprintf(msg, sizeof(msg), "GROUP_INVITE %s %d\n", from, group_id);
  send_to_user(to, msg);
}

static void handle_group_accept(int fd, const char *user, int group_id)
{
  int ok = 0;
  pthread_mutex_lock(&state_lock);
  group_t *g = find_group_locked(group_id);
  if (g != NULL && group_has_invite(g, user) && g->member_count < MAX_GROUP_MEMBERS) {
    snprintf(g->members[g->member_count++], sizeof(g->members[0]), "%s", user);
    ok = 1;
  }
  pthread_mutex_unlock(&state_lock);
  send_fmt(fd, ok ? "GROUP_JOINED %d\n" : "ERR accept-failed\n", group_id);
}

static void handle_group_key(int fd, const char *user, int group_id)
{
  char key_hex[A2_KEY_LEN * 2 + 1];
  char members[MAX_GROUP_MEMBERS][32];
  int member_count = 0;
  int ok = 0;

  pthread_mutex_lock(&state_lock);
  group_t *g = find_group_locked(group_id);
  if (g != NULL && group_has_member(g, user)) {
    if (random_bytes(g->key, sizeof(g->key)) == 0) {
      g->has_key = 1;
      hex_encode(g->key, sizeof(g->key), key_hex, sizeof(key_hex));
      member_count = g->member_count;
      for (int i = 0; i < member_count; i++) {
        snprintf(members[i], sizeof(members[i]), "%s", g->members[i]);
      }
      ok = 1;
    }
  }
  pthread_mutex_unlock(&state_lock);
  if (!ok) {
    send_all(fd, "ERR group-key-failed\n");
    return;
  }
  for (int i = 0; i < member_count; i++) {
    char msg[A2_LINE_MAX];
    snprintf(msg, sizeof(msg), "GROUP_KEY %d %s\n", group_id, key_hex);
    send_to_user(members[i], msg);
  }
}

static void handle_group_write(int fd, const char *from, int group_id, const char *msg)
{
  char members[MAX_GROUP_MEMBERS][32];
  int member_count = 0;
  int ok = 0;

  pthread_mutex_lock(&state_lock);
  group_t *g = find_group_locked(group_id);
  if (g != NULL && group_has_member(g, from) && g->has_key) {
    member_count = g->member_count;
    for (int i = 0; i < member_count; i++) {
      snprintf(members[i], sizeof(members[i]), "%s", g->members[i]);
    }
    ok = 1;
  }
  pthread_mutex_unlock(&state_lock);
  if (!ok) {
    send_all(fd, "ERR group-write-denied\n");
    return;
  }
  for (int i = 0; i < member_count; i++) {
    char line[A2_LINE_MAX];
    snprintf(line, sizeof(line), "MSG group %d %s %s\n", group_id, from, msg);
    send_to_user(members[i], line);
  }
}

static void handle_list_files(int fd, const char *requester, const char *owner)
{
  int idx = find_user(owner);
  DIR *d;
  struct dirent *ent;
  if (idx < 0) {
    send_all(fd, "ERR unknown-user\n");
    return;
  }
  d = opendir(users[idx].root);
  if (d == NULL) {
    send_all(fd, "FILES\n");
    return;
  }
  send_fmt(fd, "FILES %s", owner);
  while ((ent = readdir(d)) != NULL) {
    char path[512];
    if (ent->d_name[0] == '.') {
      continue;
    }
    if (can_read_user_file(requester, owner, ent->d_name, path, sizeof(path))) {
      send_fmt(fd, " %s", ent->d_name);
    }
  }
  closedir(d);
  send_all(fd, "\n");
}

static void handle_request_file(int fd, const char *requester, const char *owner,
                                const char *filename, const char *host, const char *port)
{
  char path[512];
  if (!can_read_user_file(requester, owner, filename, path, sizeof(path))) {
    send_all(fd, "ERR file-denied\n");
    return;
  }
  char msg[A2_LINE_MAX];
  snprintf(msg, sizeof(msg), "FILE_REQUEST %s %s %s %s\n", requester, filename, host, port);
  send_to_user(owner, msg);
  send_all(fd, "FILE_REQUEST_SENT\n");
}

static void handle_public_key_request(int fd, const char *from, const char *target)
{
  char msg[A2_LINE_MAX];
  snprintf(msg, sizeof(msg), "PUBLIC_KEY_REQUEST %s\n", from);
  send_to_user(target, msg);
  send_all(fd, "PUBLIC_KEY_REQUEST_SENT\n");
}

static void handle_send_public_key(int fd, const char *from, const char *target, const char *key)
{
  pthread_mutex_lock(&state_lock);
  client_t *c = find_client_locked(from);
  if (c != NULL) {
    snprintf(c->public_key, sizeof(c->public_key), "%s", key);
  }
  pthread_mutex_unlock(&state_lock);
  char msg[A2_LINE_MAX];
  snprintf(msg, sizeof(msg), "PUBLIC_KEY %s %s\n", from, key);
  send_to_user(target, msg);
  send_all(fd, "PUBLIC_KEY_SENT\n");
}

static void process_command(int fd, const char *user, char *line)
{
  trim_newline(line);
  if (strcmp(line, "/who") == 0) {
    handle_who(fd);
  } else if (strncmp(line, "/write all ", 11) == 0) {
    broadcast_message(user, line + 11);
  } else if (strncmp(line, "/create group", 13) == 0) {
    char *name = line + 13;
    while (*name == ' ') {
      name++;
    }
    handle_create_group(fd, user, *name ? name : "group");
  } else if (strncmp(line, "/group invite accept ", 21) == 0) {
    handle_group_accept(fd, user, atoi(line + 21));
  } else if (strncmp(line, "/group invite ", 14) == 0) {
    char *gid = strtok(line + 14, " ");
    char *target = strtok(NULL, " ");
    if (gid == NULL || target == NULL) {
      send_all(fd, "ERR usage /group invite <group-id> <user>\n");
    } else {
      handle_group_invite(fd, user, atoi(gid), target);
    }
  } else if (strncmp(line, "/request public key ", 20) == 0) {
    handle_public_key_request(fd, user, line + 20);
  } else if (strncmp(line, "/send public key ", 17) == 0) {
    char *target = strtok(line + 17, " ");
    char *key = strtok(NULL, "");
    if (target == NULL || key == NULL) {
      send_all(fd, "ERR usage /send public key <user> <key>\n");
    } else {
      handle_send_public_key(fd, user, target, key);
    }
  } else if (strncmp(line, "/init group dhxchg ", 19) == 0) {
    handle_group_key(fd, user, atoi(line + 19));
  } else if (strncmp(line, "/write group ", 13) == 0) {
    char *gid = strtok(line + 13, " ");
    char *msg = strtok(NULL, "");
    if (gid == NULL || msg == NULL) {
      send_all(fd, "ERR usage /write group <group-id> <message>\n");
    } else {
      handle_group_write(fd, user, atoi(gid), msg);
    }
  } else if (strncmp(line, "/list user files ", 17) == 0) {
    handle_list_files(fd, user, line + 17);
  } else if (strncmp(line, "/request file ", 14) == 0) {
    char *owner = strtok(line + 14, " ");
    char *filename = strtok(NULL, " ");
    char *host = strtok(NULL, " ");
    char *port = strtok(NULL, " ");
    if (owner == NULL || filename == NULL || host == NULL || port == NULL) {
      send_all(fd, "ERR usage /request file <user> <filename> <host> <port>\n");
    } else {
      handle_request_file(fd, user, owner, filename, host, port);
    }
  } else {
    send_all(fd, "ERR unknown-command\n");
  }
}

static void *chat_client_thread(void *arg)
{
  int fd = *(int *)arg;
  free(arg);
  char user[32];
  unsigned char session[A2_KEY_LEN];
  char line[A2_LINE_MAX];

  if (authenticate_chat(fd, user, sizeof(user), session) != 0 ||
      client_slot_add(fd, user, session) < 0) {
    send_all(fd, "ERR chat-authentication-failed\n");
    close(fd);
    return NULL;
  }
  send_fmt(fd, "OK authenticated %s\n", user);
  broadcast_message("server", "user-login");

  while (recv_line(fd, line, sizeof(line)) > 0) {
    process_command(fd, user, line);
  }
  client_slot_remove(fd);
  close(fd);
  return NULL;
}

static void *chat_accept_thread(void *arg)
{
  (void)arg;
  int listener = tcp_listen(cfg.bind_host, cfg.chat_port, 32);
  if (listener < 0) {
    perror("server: chat listen");
    exit(1);
  }
  fprintf(stderr, "server: chat listening on %s:%s\n", cfg.bind_host, cfg.chat_port);
  for (;;) {
    int fd = accept(listener, NULL, NULL);
    if (fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("server: chat accept");
      continue;
    }
    int *arg_fd = malloc(sizeof(int));
    pthread_t tid;
    if (arg_fd == NULL) {
      close(fd);
      continue;
    }
    *arg_fd = fd;
    pthread_create(&tid, NULL, chat_client_thread, arg_fd);
    pthread_detach(tid);
  }
}

int main(int argc, char **argv)
{
  pthread_t kdc_tid, chat_tid;
  signal(SIGPIPE, SIG_IGN);
  if (parse_args(argc, argv) != 0) {
    return 1;
  }
  derive_ticket_key();
  if (load_users() != 0) {
    fprintf(stderr, "server: failed to load users\n");
    return 1;
  }
  if (pthread_create(&kdc_tid, NULL, kdc_accept_thread, NULL) != 0 ||
      pthread_create(&chat_tid, NULL, chat_accept_thread, NULL) != 0) {
    perror("server: pthread_create");
    return 1;
  }
  pthread_join(kdc_tid, NULL);
  pthread_join(chat_tid, NULL);
  return 0;
}
