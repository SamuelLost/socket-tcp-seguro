#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define LED_HASH "02ead54d7641d63752e368936d9b0b01"

char* get_md5(char* str) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, str, strlen(str));
    MD5_Final(hash, &md5);

    char* md5string = (char*)malloc(33);
    for (int i = 0; i < 16; i++)
        sprintf(&md5string[i * 2], "%02x", (unsigned int)hash[i]);
    return md5string;
}

int main() {
    char* str = "led\n";
    char* md5 = get_md5(str);
    if(strcmp(md5, LED_HASH) == 0) {
        printf("LED ON\n");
    } else {
        printf("LED OFF\n");
    }
    printf("%s\n", md5);
    return 0;
}