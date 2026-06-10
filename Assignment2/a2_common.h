#ifndef A2_COMMON_H
#define A2_COMMON_H

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define A2_KEY_LEN 32
#define A2_HMAC_LEN 32
#define A2_GCM_IV_LEN 12
#define A2_GCM_TAG_LEN 16
#define A2_CBC_IV_LEN 16
#define A2_LINE_MAX 4096

int random_bytes(unsigned char *buf, size_t len);
int read_all_fd(int fd, void *buf, size_t len);
int write_all_fd(int fd, const void *buf, size_t len);
ssize_t recv_line(int fd, char *buf, size_t max);
int send_all(int fd, const char *msg);
int send_fmt(int fd, const char *fmt, ...);
void trim_newline(char *s);

int hex_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len);
int hex_decode(const char *hex, unsigned char *out, size_t out_len);

int sha256_bytes(const unsigned char *data, size_t data_len, unsigned char out[A2_KEY_LEN]);
int hmac_sha256(const unsigned char *key, size_t key_len,
                const unsigned char *data, size_t data_len,
                unsigned char out[A2_HMAC_LEN]);
int derive_long_term_key(const char *user, const char *password, unsigned char out[A2_KEY_LEN]);
int derive_transfer_keys(const unsigned char *raw, size_t raw_len,
                         unsigned char enc_key[A2_KEY_LEN],
                         unsigned char mac_key[A2_KEY_LEN]);

int aes_256_gcm_encrypt(const unsigned char key[A2_KEY_LEN],
                        const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *aad, int aad_len,
                        unsigned char iv[A2_GCM_IV_LEN],
                        unsigned char tag[A2_GCM_TAG_LEN],
                        unsigned char *ciphertext);
int aes_256_gcm_decrypt(const unsigned char key[A2_KEY_LEN],
                        const unsigned char iv[A2_GCM_IV_LEN],
                        const unsigned char tag[A2_GCM_TAG_LEN],
                        const unsigned char *ciphertext, int ciphertext_len,
                        const unsigned char *aad, int aad_len,
                        unsigned char *plaintext);
int aes_256_cbc_encrypt(const unsigned char key[A2_KEY_LEN],
                        const unsigned char iv[A2_CBC_IV_LEN],
                        const unsigned char *plaintext, int plaintext_len,
                        unsigned char *ciphertext);
int aes_256_cbc_decrypt(const unsigned char key[A2_KEY_LEN],
                        const unsigned char iv[A2_CBC_IV_LEN],
                        const unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *plaintext);

int tcp_connect(const char *host, const char *port);
int tcp_listen(const char *host, const char *port, int backlog);
int load_file(const char *path, unsigned char **data, size_t *len);
int save_file_atomic(const char *path, const unsigned char *data, size_t len);
int ensure_dir(const char *path);

#endif
