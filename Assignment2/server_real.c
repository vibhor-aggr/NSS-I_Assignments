#include <stdio.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include "common.h"

typedef enum {
    DATA_READY,
    DATA_RECVD,
    DATA_FINISH
} state_enum_t;

//sem_t data_sent, data_ready;

//int data_sent=0;
//int data_ready=0;
state_enum_t thread_state = DATA_READY;

int decrypt_data(int ciphertext_len, unsigned char *key, int key_len, unsigned char *iv, char* filename);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int hmac_it(unsigned char *data, int data_len, unsigned char *key, int key_len, unsigned char *result);
void* thread_1(void* arg);
void* thread_2(void* arg);
void handleErrors(void);

int main (int argc, char* argv[])
{
    //sem_init(&sem1, 0, 1);
    while(1){
        thread_state=DATA_READY;
        buff_sent=(buffsent*)malloc(sizeof(buffsent));
        memset(buff_sent, 0, sizeof(buffsent));

        int retval;
        
        if((retval=pthread_create(&(thread_id[1]), NULL, thread_2, NULL))!=0){
            printf("Failed to create thread %d", 1);
        }
        else{
            //pthread_join(thread_id[1], NULL);
        }
        if((retval=pthread_create(&(thread_id[0]), NULL, thread_1, NULL))!=0){
            printf("Failed to create thread %d", 0);
        }
        else{
            //pthread_join(thread_id[0], NULL);
        }
        
        pthread_join(thread_id[1], NULL);    
        pthread_join(thread_id[0], NULL);    
        
        free(buff_sent);
    }
    //sem_destroy(&sem1);
    return 0;
}

void* thread_2(void* arg){
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char key[32] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                           0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                           0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                           0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
                         };

    /* A 128 bit IV
    unsigned char iv[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                          0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
                        };
    */
    
    char filename[1024];
    char* filename_ptr=&(filename[0]);
    int fd=-1;

    while(1){
        
        while(thread_state==DATA_READY);
        
        if(buff_sent->syn){
            int filename_len=decrypt(buff_sent->filename, buff_sent->filename_len, &(key[0]), buff_sent->iv, filename_ptr);
            fd= open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if(fd<0){
                perror("Open failed");
                return (void*)EXIT_FAILURE;
            }
        }
        
        int plaintext_len = decrypt_data(buff_sent->ciphertext_len, &(key[0]), 32, buff_sent->iv, filename);        
        
        if(plaintext_len==-1){
            close(fd);
            if(remove(filename)==0)
                return (void*)EXIT_FAILURE;
        }
        
        int write_status = write(fd, plaintext_ptr, plaintext_len);
        
        if (write_status == -1)
        {
            perror("Server: Error in write");
            close(fd);
            //if (enable_sem) sem_post(&sem1);
            return (void*)EXIT_FAILURE;
        }
        if(thread_state==DATA_FINISH){
            close(fd);
            return (void*)EXIT_SUCCESS;
        }

        thread_state=DATA_READY;
    }
    return (void*)EXIT_SUCCESS;
}

void* thread_1(void* arg){

    while(1){
        //sem_wait(&data_sent);
        //while(data_ready==0);
        //data_sent=1;
        while(thread_state==DATA_RECVD);

        int read_status;
        int read_cnt=0;
        while (read_cnt != sizeof(buffsent)) {
          read_status = read(fileno(stdin), (char*)buff_sent+read_cnt, sizeof(buffsent)-read_cnt);

          if (read_status == -1) {
            //perror("Server: Error in number write");
            //close(fd);
            //return EXIT_FAILURE;
            return (void*)EXIT_FAILURE;
          }
          read_cnt += read_status;
        }
        if(buff_sent->fin==1){
            thread_state=DATA_FINISH;
            return (void*)EXIT_SUCCESS;
        }
        else{
            thread_state=DATA_RECVD;            
        }
        //sem_post(&data_sent);
        //data_sent=0;
        //while (data_ready==1);
    }

    return (void*)EXIT_SUCCESS;
}

int decrypt_data(int plaintext_len, unsigned char* key, int key_len, unsigned char* iv, char* filename){
    /* Message to be encrypted 
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";
    */

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    //unsigned char ciphertext[128];

    /* Buffer for the decrypted text
    unsigned char decryptedtext[128];
    */

    int decryptedtext_len;
    //int ciphertext_len;

    #if 0
    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext_ptr, strlen ((char *)plaintext), key, iv, &((buff_sent->ciphertext)[0]));

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)&((buff_sent->ciphertext)[0]), ciphertext_len);
    #endif
    
    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(&((buff_sent->ciphertext)[0]), buff_sent->ciphertext_len, key, iv, plaintext_ptr);

    /* Add a NULL terminator. We are expecting printable text */
    plaintext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    //printf("Decrypted text is:\n");
    //printf("%s\n", plaintext);

    unsigned char hmac[1024];
    int hmac_len=hmac_it(plaintext_ptr, decryptedtext_len, key, key_len, &(hmac[0]));
    if(strncmp(buff_sent->hmac, hmac, hmac_len)!=0){
        printf("HMAC validation failed, file %s not written to disk\n", filename);
        return -1;
    }
    return decryptedtext_len; 
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int hmac_it(unsigned char* data, int data_len, unsigned char* key, int key_len, unsigned char* result){
    //const char *key;
    // The data that we're going to hash
    //char data[] = "hello world";
    // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
    // Change the length accordingly with your choosen hash engine.
    //unsigned char* result;
    unsigned int len = 20;
    //result = (unsigned char*)malloc(sizeof(char) * len);
    HMAC_CTX *ctx=HMAC_CTX_new();
    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    HMAC_Init_ex(ctx, key, key_len, EVP_sha1(), NULL);
    HMAC_Update(ctx, (unsigned char*)data, data_len);
    HMAC_Final(ctx, result, &len);
    HMAC_CTX_free(ctx);

    return len;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
