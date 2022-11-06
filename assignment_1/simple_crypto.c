#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "simple_crypto.h"

char* key;
char* tempkey;
char* str;

char* inputString(FILE* fp, size_t size){ 
//Enter while securing an area dynamically
//The size is extended by the input with the value of the provisional
    int ch;
    size_t len = 0;
    str = realloc(NULL, sizeof(*str)*size);//size is start size
    if(!str)return str;
    while(EOF!=(ch=fgetc(fp)) && ch != '\n'){
        if((ch >= '0' && ch <= '9')||(ch >= 'A' && ch <= 'Z')||(ch >= 'a' && ch <= 'z')){
            str[len++]=ch;
            if(len==size){
                str = realloc(str, sizeof(*str)*(size+=16));
                if(!str)return str;
            }
        }
    }
    str[len++]='\0';

    return realloc(str, sizeof(*str)*len);
}

/******************************One time Pad******************************/

void randomKeyGenerator(int size){
    key = (char*)calloc(size, sizeof(char));
    char c;
    bool cond;
    FILE *fp = fopen("/dev/urandom", "r");
    
    for(int i= 0; i< size;i++){
        cond = false;
        do
        {   fread(&c, 1, 1, fp);
            if(isprint(c))  
                cond = true;
        } while (cond == false);
        
        key[i] = c; 
    }
    fclose(fp);
}

char* otpEncrypt(char* text){
    int len = strlen(text);
    char a;

    for (int i = 0; i<len; i++){
            a = text[i] ^ key[i]; //XOR
            if(isprint(a))
                text[i] = a;
    }
    return text;
}

char* otpDecrypt(char* text){
    size_t len = strlen(text);
    char a;

    for (int i = 0; i<len; i++){
            a = text[i] ^ key[i]; //XOR
            if(isprint(a))
                text[i] = a;
    }
    return text;
}

void oneTimePad(){

    printf("[OTP] input: ");
    char* txt = inputString(stdin, 10);
    size_t len = strlen(txt);
    
    randomKeyGenerator(len);
    //printf("key = %s\n", key); printf("key = %d\n", (int)strlen(key));
    
    char* ciphered = otpEncrypt(txt);
    printf("[OTP] encrypted: %s\n", ciphered);
    
    char* decrypted = otpDecrypt(ciphered);
    printf("[OTP] decrypted: %s\n", decrypted);
    
    free(key); 
    free(str);
}

/******************************Caesar's Cipher******************************/

char* caesarEncrypt(char* text, int k){
    size_t len = strlen(text);
    char c;
    int num;
    for (int i = 0; i<len; i++){
        c = text[i];
        num = k;
        while(num != 0){
            if (isdigit(c)){
                c = text[i] + num;
                if(c > 57 || c <0){ // c >{0-9}
                    num = c - 57 -1;
                    text[i] = 65; //'A'
                    c = text[i];
                }
                else
                    num = 0;
            }
            if(isupper(c)){
                c = text[i] + num;
                if(c > 90 || c <0){ // c >{A-Z}
                    num = c - 90 -1;
                    text[i] = 97; //'a'
                    c = text[i];
                }
                else
                    num = 0;
            }
            if (islower(c)){
                c = text[i] + num;
                if(c > 122 || c <0){ // c >{a-z}
                    num = c - 122 -1;
                    text[i] = 48; //'0'
                    c = text[i];
                }
                else
                    num = 0;
            }
            
        }
        text[i] = c;
    }
    return text;
}

char* caesarDecrypt(char* text, int k){
    size_t len = strlen(text);
    char c;
    int num;
     for (int i = 0; i<len; i++){
        c = text[i];
        num = k;
        while(num != 0){
            if (isdigit(c)){
                c = text[i] - num;
                if(c <48 || c <0){ // c <{0-9}
                    num = 48 - c -1;
                    text[i] = 122; //'z'
                    c = text[i];
                }
                else
                    num = 0;
            }
            if(isupper(c)){
                c = text[i] - num;
                if(c < 65 || c <0){ // c <{A-Z}
                    num = 65 - c -1;
                    text[i] = 57; //'9'
                    c = text[i];
                }
                else
                    num = 0;
            }
            if (islower(c)){
                c = text[i] - num;
                if(c < 97 || c <0){ // c <{a-z}
                    num = 97 - c -1;
                    text[i] = 90; //'Z'
                    c = text[i];
                }
                else
                    num = 0;
            }
            
        }
        text[i] = c;
    }
    return text;
}

void caesar(){

    printf("[Caesars] input: ");
    char* txt = inputString(stdin, 10);
    int len = strlen(txt);

    printf("[Caesars] key: ");
    key = inputString(stdin, 10);
    int numKey = atoi(key);

    char* ciphered = caesarEncrypt(txt, numKey);
    printf("[Caesars] encrypted: %s\n", ciphered);
    
    char* decrypted = caesarDecrypt(ciphered, numKey);
    printf("[Caesars] decrypted: %s\n", decrypted);

    free(str);
}


/******************************Vigenere's Cipher******************************/

char* generateKey(char* key, int length){
    tempkey =(char*)calloc(length, sizeof(char));
    strcpy(tempkey,key);
    
    size_t len = strlen(key);
    int times = length/len;

    for(int i=1; i<times; i++){
        strcat(tempkey,key);
    }
    int mod = length%len;
    strncat(tempkey,key,mod);

    return tempkey;
}


char* vigenereEncrypt(char* text, char* key){
    size_t len = strlen(text);
    int m;
    for (int i = 0; i<len; i++){
        m = text[i] + key[i] -130;
        text[i] = (m%26) +65;
    }
    return text;
}

char* vigenereDecrypt(char* text, char* key){
    size_t len = strlen(text);
    int m;
    for (int i = 0; i<len; i++){
            m = text[i] - key[i] +26;
            text[i] = (m%26) + 65;
    }
    return text;
}

void vigenere(){
    char* txt;
    size_t lentxt;
    size_t lenkey;
    bool cond;
    
    do
    {   printf("[Vigenere] input: ");
        txt = inputString(stdin, 10);
        lentxt = strlen(txt);
        cond = true;

        for(int i=0; i<lentxt; i++){
            if(!isupper(txt[i])){
                printf("All characters of the input must be uppercase letters. Try again\n");
                cond = false;
                break;
            }
        }
    } while (cond == false);


    do
    {   printf("[Vigenere] key: ");
        key = inputString(stdin, 10);
        lenkey = strlen(key);
        cond = true;
    
        for(int i=0; i<lenkey; i++){
            if(!isupper(key[i])){
                printf("All characters of the key must be uppercase letters. Try again\n");
                cond = false;
                break;
            }
        }
    } while (cond == false);

    key = generateKey(key,lentxt);

    char* ciphered = vigenereEncrypt(txt, key);
    printf("[Vigenere] encrypted: %s\n", ciphered);
    
    char* decrypted = vigenereDecrypt(ciphered, key);
    printf("[Vigenere] decrypted: %s\n", decrypted);

    free(tempkey);
    free(str);
}