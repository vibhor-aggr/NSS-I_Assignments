#include "a2_common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SC_MAGIC "NSC1"
#define SC_HEADER_LEN 64
#define SC_MAX_NAME 255
#define SC_MAX_CIPHERTEXT (512U * 1024U * 1024U)

static uint64_t ntohll_u64(uint64_t v)
{
  uint32_t hi = ntohl((uint32_t)(v >> 32));
  uint32_t lo = ntohl((uint32_t)(v & 0xffffffffU));
  return ((uint64_t)lo << 32) | hi;
}

static int load_key_material(const char *path, unsigned char enc_key[A2_KEY_LEN],
                             unsigned char mac_key[A2_KEY_LEN])
{
  unsigned char *raw = NULL;
  size_t raw_len = 0;
  int ret;
  if (load_file(path, &raw, &raw_len) != 0 || raw_len < 16) {
    fprintf(stderr, "secure_server: key file must exist and contain at least 16 bytes\n");
    free(raw);
    return -1;
  }
  ret = derive_transfer_keys(raw, raw_len, enc_key, mac_key);
  OPENSSL_cleanse(raw, raw_len);
  free(raw);
  return ret;
}

static int build_hmac(const unsigned char mac_key[A2_KEY_LEN],
                      const unsigned char header_prefix[SC_HEADER_LEN - A2_HMAC_LEN],
                      const unsigned char *name, size_t name_len,
                      const unsigned char *ciphertext, size_t ciphertext_len,
                      unsigned char out[A2_HMAC_LEN])
{
  unsigned char *buf;
  size_t total = (SC_HEADER_LEN - A2_HMAC_LEN) + name_len + ciphertext_len;
  int ret;
  buf = malloc(total);
  if (buf == NULL) {
    return -1;
  }
  memcpy(buf, header_prefix, SC_HEADER_LEN - A2_HMAC_LEN);
  memcpy(buf + (SC_HEADER_LEN - A2_HMAC_LEN), name, name_len);
  memcpy(buf + (SC_HEADER_LEN - A2_HMAC_LEN) + name_len, ciphertext, ciphertext_len);
  ret = hmac_sha256(mac_key, A2_KEY_LEN, buf, total, out);
  OPENSSL_cleanse(buf, total);
  free(buf);
  return ret;
}

static int safe_output_path(const char *dir, const char *name, char *out, size_t out_len)
{
  if (strchr(name, '/') != NULL || strstr(name, "..") != NULL) {
    return -1;
  }
  if (snprintf(out, out_len, "%s/%s", dir, name) >= (int)out_len) {
    return -1;
  }
  return 0;
}

int main(int argc, char *argv[])
{
  const char *key_path;
  const char *output_dir = ".";
  unsigned char enc_key[A2_KEY_LEN], mac_key[A2_KEY_LEN];
  unsigned char header[SC_HEADER_LEN];
  unsigned char prefix[SC_HEADER_LEN - A2_HMAC_LEN];
  unsigned char iv[A2_CBC_IV_LEN];
  unsigned char expected[A2_HMAC_LEN];
  unsigned char *name = NULL, *ciphertext = NULL, *plaintext = NULL;
  uint32_t name_len_net;
  uint64_t cipher_len_net;
  uint32_t name_len;
  uint64_t cipher_len;
  int plaintext_len;
  char output_path[1024];
  int read_status;

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "Usage: secure_server KEY_FILE [OUTPUT_DIR]\n");
    return 1;
  }
  key_path = argv[1];
  if (argc == 3) {
    output_dir = argv[2];
  }

  if (load_key_material(key_path, enc_key, mac_key) != 0) {
    return 1;
  }

  read_status = read_all_fd(STDIN_FILENO, header, sizeof(header));
  if (read_status != 1) {
    fprintf(stderr, "secure_server: incomplete header\n");
    return 1;
  }
  if (memcmp(header, SC_MAGIC, 4) != 0) {
    fprintf(stderr, "secure_server: invalid frame magic\n");
    return 1;
  }
  memcpy(&name_len_net, header + 4, sizeof(name_len_net));
  memcpy(&cipher_len_net, header + 8, sizeof(cipher_len_net));
  name_len = ntohl(name_len_net);
  cipher_len = ntohll_u64(cipher_len_net);
  if (name_len == 0 || name_len > SC_MAX_NAME || cipher_len == 0 ||
      cipher_len > SC_MAX_CIPHERTEXT || cipher_len > INT_MAX) {
    fprintf(stderr, "secure_server: invalid frame lengths\n");
    return 1;
  }
  memcpy(iv, header + 16, sizeof(iv));
  memcpy(prefix, header, sizeof(prefix));

  name = calloc(1, name_len + 1);
  ciphertext = malloc((size_t)cipher_len);
  plaintext = malloc((size_t)cipher_len + EVP_MAX_BLOCK_LENGTH);
  if (name == NULL || ciphertext == NULL || plaintext == NULL) {
    free(name);
    free(ciphertext);
    free(plaintext);
    return 1;
  }
  if (read_all_fd(STDIN_FILENO, name, name_len) != 1 ||
      read_all_fd(STDIN_FILENO, ciphertext, (size_t)cipher_len) != 1) {
    fprintf(stderr, "secure_server: incomplete payload\n");
    free(name);
    free(ciphertext);
    free(plaintext);
    return 1;
  }

  if (build_hmac(mac_key, prefix, name, name_len, ciphertext, (size_t)cipher_len, expected) != 0 ||
      CRYPTO_memcmp(expected, header + 32, A2_HMAC_LEN) != 0) {
    fprintf(stderr, "secure_server: HMAC validation failed; output not written\n");
    free(name);
    free(ciphertext);
    free(plaintext);
    return 2;
  }

  plaintext_len = aes_256_cbc_decrypt(enc_key, iv, ciphertext, (int)cipher_len, plaintext);
  if (plaintext_len < 0) {
    fprintf(stderr, "secure_server: decryption failed\n");
    free(name);
    free(ciphertext);
    free(plaintext);
    return 1;
  }

  if (safe_output_path(output_dir, (const char *)name, output_path, sizeof(output_path)) != 0 ||
      save_file_atomic(output_path, plaintext, (size_t)plaintext_len) != 0) {
    fprintf(stderr, "secure_server: failed to write output file\n");
    free(name);
    free(ciphertext);
    free(plaintext);
    return 1;
  }

  printf("secure_server: wrote %s (%d bytes)\n", output_path, plaintext_len);
  OPENSSL_cleanse(plaintext, (size_t)plaintext_len);
  free(name);
  free(ciphertext);
  free(plaintext);
  return 0;
}
