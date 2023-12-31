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
    DATA_SENT,
    DATA_FINISH
} state_enum_t;

//sem_t data_sent, data_ready;

//int data_sent=0;
//int data_ready=0;
state_enum_t thread_state = DATA_SENT;
int corrupt_data=FALSE;

int encrypt_data(int plaintext_len, unsigned char *key, int key_len, unsigned char *iv);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int hmac_it(unsigned char *data, int data_len, unsigned char *key, int key_len, unsigned char *result);
void* thread_1(void* arg);
void* thread_2(void* arg);
void handleErrors(void);

int main (int argc, char* argv[])
{
    if(argc<3 || argc>4){
        return EXIT_FAILURE;
    }
    if (argc == 4) {
        if (!strcmp(argv[3], "-corrupt_data")) corrupt_data=TRUE;
    }

    //sem_init(&sem1, 0, 1);

    buff_sent=(buffsent*)malloc(sizeof(buffsent));

    int retval;
    
    if((retval=pthread_create(&(thread_id[1]), NULL, thread_2, NULL))!=0){
        printf("Failed to create thread %d", 1);
    }
    else{
        //pthread_join(thread_id[1], NULL);
    }
    if((retval=pthread_create(&(thread_id[0]), NULL, thread_1, (void*)(argv)))!=0){
        printf("Failed to create thread %d", 0);
    }
    else{
        //pthread_join(thread_id[0], NULL);
    }
    
    pthread_join(thread_id[0], NULL);    
    pthread_join(thread_id[1], NULL);    
        
    free(buff_sent);
    //sem_destroy(&sem1);
    return 0;
}

void* thread_1(void* arg){
    
    char** argv=(char**)arg;
    char* filename=argv[1];
    int fd= open(filename, O_RDONLY);
    if(fd<0){
        perror("Open failed");
        thread_state=DATA_FINISH;
        return (void*)EXIT_FAILURE;
    }
    
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

    /* A 128 bit IV */
#if 0    
    unsigned char iv[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                          0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
                        };
#endif
    
    unsigned char iv[16];
    unsigned char* ivptr=&iv[0];
    get_random(ivptr);
    
    //buff_sent->seqno=0;
    buff_sent->filename_len=encrypt(argv[2], strlen(argv[2])+1, &(key[0]), &(iv[0]), &((buff_sent->filename)[0]));
    buff_sent->syn=1;
    for(int i=0;i<16;i++){
        (buff_sent->iv)[i]=iv[i];
    }
    //buff_sent->iv=strcpy();

    struct stat st;
    stat(filename, &st);
    int filesize = (int)(st.st_size);

    while(1){
        while(thread_state==DATA_READY);
        int read_status = read(fd, plaintext_ptr, 1024*512);
        
        if (read_status == -1)
        {
            //perror("Server: Error in reading number");
            close(fd);
            thread_state=DATA_FINISH;
            //if (enable_sem) sem_post(&sem1);
            return (void*)EXIT_FAILURE;
        }   
        else if(read_status == 0){
            close(fd);
            thread_state=DATA_FINISH;
            return (void*)EXIT_SUCCESS;
            //pthread_exit(NULL);
        }  
        else if(read_status!=0){
            //sem_wait(&sem1);
            //while(data_sent==1);
            //data_ready=0;
            filesize-=read_status;
            if(filesize==0){
                buff_sent->fin=1;
            }
            buff_sent->ciphertext_len=encrypt_data(read_status, &(key[0]), 32, &(iv[0]));
            
            //data_ready=1;
            //sem_post(&sem1);
        }
        thread_state=DATA_READY;
    }
    return (void*)EXIT_SUCCESS;
}

void* thread_2(void* arg){

    while(1){
        //sem_wait(&data_sent);
        //while(data_ready==0);
        //data_sent=1;
        while(thread_state==DATA_SENT);

        if(thread_state==DATA_FINISH){
            return (void*)EXIT_SUCCESS;
        }

        int write_status;
        int write_cnt=0;
        while (write_cnt != sizeof(buffsent)) {
          write_status = write(fileno(stdout), (char*)buff_sent+write_cnt, sizeof(buffsent)-write_cnt);

          if (write_status == -1) {
            //perror("Server: Error in number write");
            //close(fd);
            //return EXIT_FAILURE;
            return (void*)EXIT_FAILURE;
          }
           write_cnt += write_status;
        }
        //check write_status
        if(buff_sent->syn==1){
            buff_sent->syn=0;
        }
        //buff_sent->seqno++;
        //sem_post(&data_sent);
        //data_sent=0;
        //while (data_ready==1);
        thread_state=DATA_SENT;
    }

    return (void*)EXIT_SUCCESS;
}

int encrypt_data(int plaintext_len, unsigned char* key, int key_len, unsigned char* iv){
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

    //int decryptedtext_len;
    int ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext_ptr, plaintext_len, key, iv, &((buff_sent->ciphertext)[0]));
    if (corrupt_data) buff_sent->ciphertext[0] ^= 0xff;

    /* Do something useful with the ciphertext here */
    //printf("Ciphertext is:\n");
    //BIO_dump_fp (stdout, (const char *)&((buff_sent->ciphertext)[0]), ciphertext_len);

    int hmac_len=hmac_it(plaintext_ptr, plaintext_len, key, key_len, &((buff_sent->hmac)[0]));

    #if 0
    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, &(key[0]), &(iv[0]),
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);
    #endif
    return ciphertext_len;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
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
