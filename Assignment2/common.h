#ifndef _COMMON_H
#define _COMMON_H

#define TRUE 1
#define FALSE 0

#include <openssl/hmac.h>
void get_random(unsigned char* buffer);

pthread_t thread_id[2];
unsigned char plaintext[1024*512];
unsigned char* plaintext_ptr=&plaintext[0];

typedef struct buffsent{
    int syn;
    int fin;
    //int seqno;
    unsigned char filename[1024];
    int filename_len;
    unsigned char ciphertext[1024*512+10*1024];
    int ciphertext_len;
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned char iv[16];
} buffsent;

buffsent* buff_sent;

#endif
