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

static uint64_t htonll_u64(uint64_t v)
{
  uint32_t hi = htonl((uint32_t)(v >> 32));
  uint32_t lo = htonl((uint32_t)(v & 0xffffffffU));
  return ((uint64_t)lo << 32) | hi;
}

static int load_key_material(const char *path, unsigned char enc_key[A2_KEY_LEN],
                             unsigned char mac_key[A2_KEY_LEN])
{
  unsigned char *raw = NULL;
  size_t raw_len = 0;
  int ret;
  if (load_file(path, &raw, &raw_len) != 0 || raw_len < 16) {
    fprintf(stderr, "secure_client: key file must exist and contain at least 16 bytes\n");
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

int main(int argc, char *argv[])
{
  const char *input_path;
  const char *output_name;
  const char *key_path;
  int corrupt = 0;
  unsigned char enc_key[A2_KEY_LEN], mac_key[A2_KEY_LEN];
  unsigned char *plaintext = NULL, *ciphertext = NULL;
  size_t plaintext_len = 0;
  int ciphertext_len;
  unsigned char iv[A2_CBC_IV_LEN];
  unsigned char header[SC_HEADER_LEN];
  unsigned char prefix[SC_HEADER_LEN - A2_HMAC_LEN];
  uint32_t name_len_be;
  uint64_t cipher_len_be;
  size_t name_len;

  if (argc < 4 || argc > 5) {
    fprintf(stderr, "Usage: secure_client INPUT_FILE REMOTE_OUTPUT_NAME KEY_FILE [-corrupt_data]\n");
    return 1;
  }
  input_path = argv[1];
  output_name = argv[2];
  key_path = argv[3];
  if (argc == 5 && strcmp(argv[4], "-corrupt_data") == 0) {
    corrupt = 1;
  } else if (argc == 5) {
    fprintf(stderr, "secure_client: unknown option %s\n", argv[4]);
    return 1;
  }

  name_len = strlen(output_name);
  if (name_len == 0 || name_len > SC_MAX_NAME || strchr(output_name, '/') != NULL) {
    fprintf(stderr, "secure_client: output name must be a simple filename up to %d bytes\n", SC_MAX_NAME);
    return 1;
  }

  if (load_key_material(key_path, enc_key, mac_key) != 0 ||
      load_file(input_path, &plaintext, &plaintext_len) != 0 ||
      plaintext_len > INT_MAX - EVP_MAX_BLOCK_LENGTH ||
      random_bytes(iv, sizeof(iv)) != 0) {
    fprintf(stderr, "secure_client: failed to prepare encrypted payload\n");
    free(plaintext);
    return 1;
  }

  ciphertext = malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
  if (ciphertext == NULL) {
    free(plaintext);
    return 1;
  }
  ciphertext_len = aes_256_cbc_encrypt(enc_key, iv, plaintext, (int)plaintext_len, ciphertext);
  if (ciphertext_len < 0) {
    fprintf(stderr, "secure_client: encryption failed\n");
    free(plaintext);
    free(ciphertext);
    return 1;
  }

  memset(header, 0, sizeof(header));
  memcpy(header, SC_MAGIC, 4);
  name_len_be = htonl((uint32_t)name_len);
  cipher_len_be = htonll_u64((uint64_t)ciphertext_len);
  memcpy(header + 4, &name_len_be, sizeof(name_len_be));
  memcpy(header + 8, &cipher_len_be, sizeof(cipher_len_be));
  memcpy(header + 16, iv, sizeof(iv));
  memcpy(prefix, header, sizeof(prefix));
  if (build_hmac(mac_key, prefix, (const unsigned char *)output_name, name_len,
                 ciphertext, (size_t)ciphertext_len, header + 32) != 0) {
    fprintf(stderr, "secure_client: HMAC failed\n");
    free(plaintext);
    free(ciphertext);
    return 1;
  }

  if (corrupt && ciphertext_len > 0) {
    ciphertext[0] ^= 0xff;
  }

  if (write_all_fd(STDOUT_FILENO, header, sizeof(header)) != 0 ||
      write_all_fd(STDOUT_FILENO, output_name, name_len) != 0 ||
      write_all_fd(STDOUT_FILENO, ciphertext, (size_t)ciphertext_len) != 0) {
    perror("secure_client: write");
    free(plaintext);
    free(ciphertext);
    return 1;
  }

  OPENSSL_cleanse(plaintext, plaintext_len);
  free(plaintext);
  free(ciphertext);
  return 0;
}
