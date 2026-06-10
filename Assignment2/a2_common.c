#define _GNU_SOURCE
#include "a2_common.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int random_bytes(unsigned char *buf, size_t len)
{
  return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

int read_all_fd(int fd, void *buf, size_t len)
{
  unsigned char *p = buf;
  size_t done = 0;
  while (done < len) {
    ssize_t ret = read(fd, p + done, len - done);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (ret == 0) {
      return 0;
    }
    done += (size_t)ret;
  }
  return 1;
}

int write_all_fd(int fd, const void *buf, size_t len)
{
  const unsigned char *p = buf;
  size_t done = 0;
  while (done < len) {
    ssize_t ret = write(fd, p + done, len - done);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (ret == 0) {
      return -1;
    }
    done += (size_t)ret;
  }
  return 0;
}

ssize_t recv_line(int fd, char *buf, size_t max)
{
  size_t pos = 0;
  if (max == 0) {
    return -1;
  }
  while (pos + 1 < max) {
    char c;
    ssize_t ret = read(fd, &c, 1);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (ret == 0) {
      break;
    }
    buf[pos++] = c;
    if (c == '\n') {
      break;
    }
  }
  buf[pos] = '\0';
  return (ssize_t)pos;
}

int send_all(int fd, const char *msg)
{
  return write_all_fd(fd, msg, strlen(msg));
}

int send_fmt(int fd, const char *fmt, ...)
{
  char buf[A2_LINE_MAX];
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0 || (size_t)n >= sizeof(buf)) {
    return -1;
  }
  return send_all(fd, buf);
}

void trim_newline(char *s)
{
  size_t n;
  if (s == NULL) {
    return;
  }
  n = strlen(s);
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
    s[--n] = '\0';
  }
}

int hex_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
  static const char hexdigits[] = "0123456789abcdef";
  if (out_len < in_len * 2 + 1) {
    return -1;
  }
  for (size_t i = 0; i < in_len; i++) {
    out[i * 2] = hexdigits[in[i] >> 4];
    out[i * 2 + 1] = hexdigits[in[i] & 0x0f];
  }
  out[in_len * 2] = '\0';
  return 0;
}

static int hex_value(char c)
{
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

int hex_decode(const char *hex, unsigned char *out, size_t out_len)
{
  size_t len;
  if (hex == NULL) {
    return -1;
  }
  len = strlen(hex);
  if (len % 2 != 0 || out_len < len / 2) {
    return -1;
  }
  for (size_t i = 0; i < len / 2; i++) {
    int hi = hex_value(hex[i * 2]);
    int lo = hex_value(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return (int)(len / 2);
}

int sha256_bytes(const unsigned char *data, size_t data_len, unsigned char out[A2_KEY_LEN])
{
  unsigned int out_len = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    return -1;
  }
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(ctx, data, data_len) != 1 ||
      EVP_DigestFinal_ex(ctx, out, &out_len) != 1 || out_len != A2_KEY_LEN) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  EVP_MD_CTX_free(ctx);
  return 0;
}

int hmac_sha256(const unsigned char *key, size_t key_len,
                const unsigned char *data, size_t data_len,
                unsigned char out[A2_HMAC_LEN])
{
  unsigned int out_len = 0;
  if (HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len) == NULL) {
    return -1;
  }
  return out_len == A2_HMAC_LEN ? 0 : -1;
}

int derive_long_term_key(const char *user, const char *password, unsigned char out[A2_KEY_LEN])
{
  char salt[256];
  int n;
  if (user == NULL || password == NULL) {
    return -1;
  }
  n = snprintf(salt, sizeof(salt), "nss-a2:%s", user);
  if (n < 0 || (size_t)n >= sizeof(salt)) {
    return -1;
  }
  return PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           (const unsigned char *)salt, (int)strlen(salt),
                           120000, EVP_sha256(), A2_KEY_LEN, out) == 1
             ? 0
             : -1;
}

int derive_transfer_keys(const unsigned char *raw, size_t raw_len,
                         unsigned char enc_key[A2_KEY_LEN],
                         unsigned char mac_key[A2_KEY_LEN])
{
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;

  if (raw == NULL || raw_len == 0) {
    return -1;
  }
  const char *enc_label = "nss-secure-copy-encryption";
  const char *mac_label = "nss-secure-copy-authentication";

  if (!HMAC(EVP_sha256(), raw, (int)raw_len,
            (const unsigned char *)enc_label, strlen(enc_label),
            enc_key, &digest_len) ||
      digest_len != A2_KEY_LEN) {
    return -1;
  }
  if (!HMAC(EVP_sha256(), raw, (int)raw_len,
            (const unsigned char *)mac_label, strlen(mac_label),
            digest, &digest_len) ||
      digest_len != A2_KEY_LEN) {
    return -1;
  }
  memcpy(mac_key, digest, A2_KEY_LEN);
  return 0;
}

int aes_256_gcm_encrypt(const unsigned char key[A2_KEY_LEN],
                        const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *aad, int aad_len,
                        unsigned char iv[A2_GCM_IV_LEN],
                        unsigned char tag[A2_GCM_TAG_LEN],
                        unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  int ciphertext_len = 0;
  if (ctx == NULL || random_bytes(iv, A2_GCM_IV_LEN) != 0) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, A2_GCM_IV_LEN, NULL) != 1 ||
      EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  if (aad != NULL && aad_len > 0 &&
      EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len = len;
  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, A2_GCM_TAG_LEN, tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int aes_256_gcm_decrypt(const unsigned char key[A2_KEY_LEN],
                        const unsigned char iv[A2_GCM_IV_LEN],
                        const unsigned char tag[A2_GCM_TAG_LEN],
                        const unsigned char *ciphertext, int ciphertext_len,
                        const unsigned char *aad, int aad_len,
                        unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  int plaintext_len = 0;
  int ret;
  if (ctx == NULL) {
    return -1;
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, A2_GCM_IV_LEN, NULL) != 1 ||
      EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  if (aad != NULL && aad_len > 0 &&
      EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len = len;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, A2_GCM_TAG_LEN, (void *)tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  EVP_CIPHER_CTX_free(ctx);
  if (ret != 1) {
    return -1;
  }
  plaintext_len += len;
  return plaintext_len;
}

int aes_256_cbc_encrypt(const unsigned char key[A2_KEY_LEN],
                        const unsigned char iv[A2_CBC_IV_LEN],
                        const unsigned char *plaintext, int plaintext_len,
                        unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  int ciphertext_len = 0;
  if (ctx == NULL) {
    return -1;
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
      EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len = len;
  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int aes_256_cbc_decrypt(const unsigned char key[A2_KEY_LEN],
                        const unsigned char iv[A2_CBC_IV_LEN],
                        const unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  int plaintext_len = 0;
  if (ctx == NULL) {
    return -1;
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
      EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len = len;
  if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

int tcp_connect(const char *host, const char *port)
{
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  struct addrinfo *rp;
  int fd = -1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port, &hints, &res) != 0) {
    return -1;
  }

  for (rp = res; rp != NULL; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) {
      continue;
    }
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

int tcp_listen(const char *host, const char *port, int backlog)
{
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  struct addrinfo *rp;
  int fd = -1;
  int yes = 1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(host, port, &hints, &res) != 0) {
    return -1;
  }

  for (rp = res; rp != NULL; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) {
      continue;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fd, backlog) == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

int load_file(const char *path, unsigned char **data, size_t *len)
{
  FILE *f;
  long size;
  unsigned char *buf;

  if (path == NULL || data == NULL || len == NULL) {
    return -1;
  }

  f = fopen(path, "rb");
  if (f == NULL) {
    return -1;
  }
  if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return -1;
  }
  buf = malloc((size_t)size + 1);
  if (buf == NULL) {
    fclose(f);
    return -1;
  }
  if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
    free(buf);
    fclose(f);
    return -1;
  }
  fclose(f);
  buf[size] = '\0';
  *data = buf;
  *len = (size_t)size;
  return 0;
}

int save_file_atomic(const char *path, const unsigned char *data, size_t len)
{
  char tmp[1024];
  int fd;
  int n;

  n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
  if (n < 0 || (size_t)n >= sizeof(tmp)) {
    return -1;
  }
  fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  if (fd < 0) {
    return -1;
  }
  if (write_all_fd(fd, data, len) != 0) {
    close(fd);
    unlink(tmp);
    return -1;
  }
  if (close(fd) != 0 || rename(tmp, path) != 0) {
    unlink(tmp);
    return -1;
  }
  return 0;
}

int ensure_dir(const char *path)
{
  if (mkdir(path, 0700) == 0 || errno == EEXIST) {
    return 0;
  }
  return -1;
}
