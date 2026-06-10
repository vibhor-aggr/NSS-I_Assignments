#define _GNU_SOURCE
#include "a2_common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
  char user[32];
  char password[128];
  char host[128];
  char kdc_port[16];
  char chat_port[16];
  char file_root[256];
  char download_dir[256];
  char cert_path[256];
  char key_path[256];
  char public_key[2048];
} client_config_t;

typedef struct {
  char port[16];
  char download_dir[256];
  char cert_path[256];
  char key_path[256];
} tls_recv_args_t;

static client_config_t cfg = {
    .host = "127.0.0.1",
    .kdc_port = "9000",
    .chat_port = "9001",
    .download_dir = "downloads",
    .cert_path = "certs/requester.crt",
    .key_path = "certs/requester.key",
};

static unsigned char long_key[A2_KEY_LEN];
static unsigned char session_key[A2_KEY_LEN];
static char ticket_iv_hex[128];
static char ticket_tag_hex[128];
static char ticket_ct_hex[4096];

static void usage(const char *argv0)
{
  fprintf(stderr,
          "Usage: %s --user USER --password PASSWORD [--host HOST] [--kdc-port PORT] "
          "[--chat-port PORT] [--file-root DIR] [--download-dir DIR] "
          "[--cert CERT] [--key KEY] [--public-key TEXT]\n",
          argv0);
}

static int parse_args(int argc, char **argv)
{
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
      snprintf(cfg.user, sizeof(cfg.user), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
      snprintf(cfg.password, sizeof(cfg.password), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
      snprintf(cfg.host, sizeof(cfg.host), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--kdc-port") == 0 && i + 1 < argc) {
      snprintf(cfg.kdc_port, sizeof(cfg.kdc_port), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--chat-port") == 0 && i + 1 < argc) {
      snprintf(cfg.chat_port, sizeof(cfg.chat_port), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--file-root") == 0 && i + 1 < argc) {
      snprintf(cfg.file_root, sizeof(cfg.file_root), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--download-dir") == 0 && i + 1 < argc) {
      snprintf(cfg.download_dir, sizeof(cfg.download_dir), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      snprintf(cfg.cert_path, sizeof(cfg.cert_path), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      snprintf(cfg.key_path, sizeof(cfg.key_path), "%s", argv[++i]);
    } else if (strcmp(argv[i], "--public-key") == 0 && i + 1 < argc) {
      snprintf(cfg.public_key, sizeof(cfg.public_key), "%s", argv[++i]);
    } else {
      usage(argv[0]);
      return -1;
    }
  }
  if (cfg.user[0] == '\0' || cfg.password[0] == '\0') {
    usage(argv[0]);
    return -1;
  }
  if (cfg.file_root[0] == '\0') {
    snprintf(cfg.file_root, sizeof(cfg.file_root), "files/%s", cfg.user);
  }
  if (cfg.public_key[0] == '\0') {
    snprintf(cfg.public_key, sizeof(cfg.public_key), "PUBKEY-%s", cfg.user);
  }
  return 0;
}

static int make_nonce_hex(char *out, size_t out_len)
{
  unsigned char nonce[16];
  if (random_bytes(nonce, sizeof(nonce)) != 0) {
    return -1;
  }
  return hex_encode(nonce, sizeof(nonce), out, out_len);
}

static int authenticate_with_kdc(void)
{
  int fd;
  char nonce_hex[33];
  char hmac_input[512];
  unsigned char hmac[A2_HMAC_LEN];
  char hmac_hex[A2_HMAC_LEN * 2 + 1];
  char line[A2_LINE_MAX];
  char *status;
  char *iv_hex;
  char *tag_hex;
  char *ct_hex;
  unsigned char iv[A2_GCM_IV_LEN], tag[A2_GCM_TAG_LEN], ciphertext[4096], plaintext[4096];
  int ct_len, pt_len;
  char *session_hex;
  char *expiry_s;
  char *ticket_iv;
  char *ticket_tag;
  char *ticket_ct;
  long ts = time(NULL);

  if (derive_long_term_key(cfg.user, cfg.password, long_key) != 0 ||
      make_nonce_hex(nonce_hex, sizeof(nonce_hex)) != 0) {
    return -1;
  }
  snprintf(hmac_input, sizeof(hmac_input), "AUTH|%s|%s|%ld", cfg.user, nonce_hex, ts);
  if (hmac_sha256(long_key, A2_KEY_LEN, (const unsigned char *)hmac_input,
                  strlen(hmac_input), hmac) != 0 ||
      hex_encode(hmac, sizeof(hmac), hmac_hex, sizeof(hmac_hex)) != 0) {
    return -1;
  }

  fd = tcp_connect(cfg.host, cfg.kdc_port);
  if (fd < 0) {
    perror("client: connect KDC");
    return -1;
  }
  send_fmt(fd, "AUTH %s %s %ld %s\n", cfg.user, nonce_hex, ts, hmac_hex);
  if (recv_line(fd, line, sizeof(line)) <= 0) {
    close(fd);
    return -1;
  }
  close(fd);
  trim_newline(line);
  status = strtok(line, " ");
  iv_hex = strtok(NULL, " ");
  tag_hex = strtok(NULL, " ");
  ct_hex = strtok(NULL, " ");
  if (status == NULL || strcmp(status, "OK") != 0 || iv_hex == NULL || tag_hex == NULL || ct_hex == NULL) {
    fprintf(stderr, "client: KDC rejected authentication\n");
    return -1;
  }
  if (hex_decode(iv_hex, iv, sizeof(iv)) != A2_GCM_IV_LEN ||
      hex_decode(tag_hex, tag, sizeof(tag)) != A2_GCM_TAG_LEN ||
      (ct_len = hex_decode(ct_hex, ciphertext, sizeof(ciphertext))) <= 0) {
    return -1;
  }
  pt_len = aes_256_gcm_decrypt(long_key, iv, tag, ciphertext, ct_len, NULL, 0, plaintext);
  if (pt_len < 0 || pt_len >= (int)sizeof(plaintext)) {
    fprintf(stderr, "client: failed to decrypt KDC response\n");
    return -1;
  }
  plaintext[pt_len] = '\0';
  session_hex = strtok((char *)plaintext, " ");
  expiry_s = strtok(NULL, " ");
  ticket_iv = strtok(NULL, " ");
  ticket_tag = strtok(NULL, " ");
  ticket_ct = strtok(NULL, " ");
  if (session_hex == NULL || expiry_s == NULL || ticket_iv == NULL || ticket_tag == NULL || ticket_ct == NULL ||
      hex_decode(session_hex, session_key, A2_KEY_LEN) != A2_KEY_LEN) {
    return -1;
  }
  (void)expiry_s;
  snprintf(ticket_iv_hex, sizeof(ticket_iv_hex), "%s", ticket_iv);
  snprintf(ticket_tag_hex, sizeof(ticket_tag_hex), "%s", ticket_tag);
  snprintf(ticket_ct_hex, sizeof(ticket_ct_hex), "%s", ticket_ct);
  return 0;
}

static int connect_chat(void)
{
  int fd;
  char nonce_hex[33];
  char hmac_input[512];
  unsigned char hmac[A2_HMAC_LEN];
  char hmac_hex[A2_HMAC_LEN * 2 + 1];
  char line[A2_LINE_MAX];

  if (make_nonce_hex(nonce_hex, sizeof(nonce_hex)) != 0) {
    return -1;
  }
  snprintf(hmac_input, sizeof(hmac_input), "CHAT|%s|%s", cfg.user, nonce_hex);
  if (hmac_sha256(session_key, A2_KEY_LEN, (const unsigned char *)hmac_input,
                  strlen(hmac_input), hmac) != 0 ||
      hex_encode(hmac, sizeof(hmac), hmac_hex, sizeof(hmac_hex)) != 0) {
    return -1;
  }
  fd = tcp_connect(cfg.host, cfg.chat_port);
  if (fd < 0) {
    perror("client: connect chat");
    return -1;
  }
  send_fmt(fd, "TICKET %s %s %s %s %s\n",
           ticket_iv_hex, ticket_tag_hex, ticket_ct_hex, nonce_hex, hmac_hex);
  if (recv_line(fd, line, sizeof(line)) <= 0) {
    close(fd);
    return -1;
  }
  fputs(line, stdout);
  if (strncmp(line, "OK authenticated", 16) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int send_file_tls(const char *host, const char *port, const char *filename)
{
  char path[512];
  unsigned char *data = NULL;
  size_t data_len = 0;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  int fd = -1;
  int ret = -1;
  char header[512];

  if (strchr(filename, '/') != NULL || strstr(filename, "..") != NULL ||
      snprintf(path, sizeof(path), "%s/%s", cfg.file_root, filename) >= (int)sizeof(path) ||
      load_file(path, &data, &data_len) != 0) {
    fprintf(stderr, "client: cannot read requested file %s\n", filename);
    return -1;
  }

  ctx = SSL_CTX_new(TLS_client_method());
  for (int attempt = 0; attempt < 30; attempt++) {
    fd = tcp_connect(host, port);
    if (fd >= 0) {
      break;
    }
    usleep(100000);
  }
  if (ctx == NULL || fd < 0) {
    goto out;
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  ssl = SSL_new(ctx);
  if (ssl == NULL) {
    goto out;
  }
  SSL_set_fd(ssl, fd);
  if (SSL_connect(ssl) != 1) {
    goto out;
  }
  snprintf(header, sizeof(header), "FILE %s %zu\n", filename, data_len);
  if (SSL_write(ssl, header, (int)strlen(header)) <= 0 ||
      (data_len > 0 && SSL_write(ssl, data, (int)data_len) <= 0)) {
    goto out;
  }
  ret = 0;

out:
  if (ssl != NULL) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  if (fd >= 0) {
    close(fd);
  }
  SSL_CTX_free(ctx);
  free(data);
  return ret;
}

static int ssl_read_line(SSL *ssl, char *buf, size_t max)
{
  size_t pos = 0;
  while (pos + 1 < max) {
    char c;
    int ret = SSL_read(ssl, &c, 1);
    if (ret <= 0) {
      return -1;
    }
    buf[pos++] = c;
    if (c == '\n') {
      break;
    }
  }
  buf[pos] = '\0';
  return (int)pos;
}

static void *tls_receive_thread(void *arg)
{
  tls_recv_args_t *args = arg;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  int listener = -1;
  int fd = -1;
  char line[512];
  char *kind;
  char *filename;
  char *len_s;
  size_t file_len;
  unsigned char *buf = NULL;
  char output_path[512];

  ensure_dir(args->download_dir);
  ctx = SSL_CTX_new(TLS_server_method());
  if (ctx == NULL ||
      SSL_CTX_use_certificate_file(ctx, args->cert_path, SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_use_PrivateKey_file(ctx, args->key_path, SSL_FILETYPE_PEM) != 1) {
    fprintf(stderr, "client: TLS certificate/key not available; run make certs\n");
    goto out;
  }
  listener = tcp_listen("0.0.0.0", args->port, 1);
  if (listener < 0) {
    perror("client: file listen");
    goto out;
  }
  fd = accept(listener, NULL, NULL);
  if (fd < 0) {
    goto out;
  }
  ssl = SSL_new(ctx);
  if (ssl == NULL) {
    goto out;
  }
  SSL_set_fd(ssl, fd);
  if (SSL_accept(ssl) != 1 || ssl_read_line(ssl, line, sizeof(line)) <= 0) {
    goto out;
  }
  trim_newline(line);
  kind = strtok(line, " ");
  filename = strtok(NULL, " ");
  len_s = strtok(NULL, " ");
  if (kind == NULL || strcmp(kind, "FILE") != 0 || filename == NULL || len_s == NULL ||
      strchr(filename, '/') != NULL || strstr(filename, "..") != NULL) {
    goto out;
  }
  file_len = strtoull(len_s, NULL, 10);
  buf = malloc(file_len + 1);
  if (buf == NULL) {
    goto out;
  }
  size_t done = 0;
  while (done < file_len) {
    int ret = SSL_read(ssl, buf + done, (int)(file_len - done));
    if (ret <= 0) {
      goto out;
    }
    done += (size_t)ret;
  }
  snprintf(output_path, sizeof(output_path), "%s/%s", args->download_dir, filename);
  if (save_file_atomic(output_path, buf, file_len) == 0) {
    fprintf(stderr, "client: received TLS file %s\n", output_path);
  }

out:
  free(buf);
  if (ssl != NULL) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  if (fd >= 0) {
    close(fd);
  }
  if (listener >= 0) {
    close(listener);
  }
  SSL_CTX_free(ctx);
  free(args);
  return NULL;
}

static void maybe_start_file_receiver(const char *line)
{
  if (strncmp(line, "/request file ", 14) != 0) {
    return;
  }
  char copy[A2_LINE_MAX];
  snprintf(copy, sizeof(copy), "%s", line + 14);
  char *owner = strtok(copy, " ");
  char *filename = strtok(NULL, " ");
  char *host = strtok(NULL, " ");
  char *port = strtok(NULL, " \n\r");
  (void)owner;
  (void)filename;
  (void)host;
  if (port == NULL) {
    return;
  }
  tls_recv_args_t *args = calloc(1, sizeof(*args));
  pthread_t tid;
  if (args == NULL) {
    return;
  }
  snprintf(args->port, sizeof(args->port), "%s", port);
  snprintf(args->download_dir, sizeof(args->download_dir), "%s", cfg.download_dir);
  snprintf(args->cert_path, sizeof(args->cert_path), "%s", cfg.cert_path);
  snprintf(args->key_path, sizeof(args->key_path), "%s", cfg.key_path);
  if (pthread_create(&tid, NULL, tls_receive_thread, args) == 0) {
    pthread_detach(tid);
  } else {
    free(args);
  }
}

static void handle_server_line(const char *line)
{
  fputs(line, stdout);
  if (strncmp(line, "FILE_REQUEST ", 13) == 0) {
    char copy[A2_LINE_MAX];
    char *requester;
    char *filename;
    char *host;
    char *port;
    snprintf(copy, sizeof(copy), "%s", line + 13);
    trim_newline(copy);
    requester = strtok(copy, " ");
    filename = strtok(NULL, " ");
    host = strtok(NULL, " ");
    port = strtok(NULL, " ");
    (void)requester;
    if (filename != NULL && host != NULL && port != NULL) {
      if (send_file_tls(host, port, filename) != 0) {
        fprintf(stderr, "client: TLS file send failed\n");
      }
    }
  } else if (strncmp(line, "PUBLIC_KEY_REQUEST ", 19) == 0) {
    fprintf(stderr, "client: use /send public key <user> %s to respond\n", cfg.public_key);
  }
}

int main(int argc, char **argv)
{
  int chat_fd;
  fd_set rfds;
  char line[A2_LINE_MAX];

  signal(SIGPIPE, SIG_IGN);
  SSL_library_init();
  SSL_load_error_strings();

  if (parse_args(argc, argv) != 0) {
    return 1;
  }
  if (authenticate_with_kdc() != 0) {
    fprintf(stderr, "client: KDC authentication failed\n");
    return 1;
  }
  chat_fd = connect_chat();
  if (chat_fd < 0) {
    fprintf(stderr, "client: chat authentication failed\n");
    return 1;
  }

  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    FD_SET(chat_fd, &rfds);
    int maxfd = chat_fd > STDIN_FILENO ? chat_fd : STDIN_FILENO;
    if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("client: select");
      break;
    }
    if (FD_ISSET(chat_fd, &rfds)) {
      ssize_t n = recv_line(chat_fd, line, sizeof(line));
      if (n <= 0) {
        fprintf(stderr, "client: server disconnected\n");
        break;
      }
      handle_server_line(line);
    }
    if (FD_ISSET(STDIN_FILENO, &rfds)) {
      if (fgets(line, sizeof(line), stdin) == NULL) {
        break;
      }
      maybe_start_file_receiver(line);
      if (send_all(chat_fd, line) != 0) {
        break;
      }
    }
  }

  close(chat_fd);
  return 0;
}
