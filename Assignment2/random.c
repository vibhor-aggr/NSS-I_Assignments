#include <stdio.h>
#include <stdlib.h>

void get_random(unsigned char* buffer)
{
    FILE *ptr = NULL;
    ptr = fopen("/dev/urandom","rb");
    if(ptr==NULL){
        perror("Failed to open /dev/urandom");
        return;
    }
    fread(buffer, sizeof(char)*8, 1, ptr); 
    fread(buffer+8, sizeof(char)*8, 1, ptr);     
    fclose(ptr);
//  for(int i = 0; i<16; i++)
//      printf("%u ", buffer[i]);
    
    return;
}

#if 0
int main(){
    unsigned char buffer[16];
    unsigned char* bufferptr=&buffer[0];
    get_random(bufferptr);
    return 0;
}
#endif
