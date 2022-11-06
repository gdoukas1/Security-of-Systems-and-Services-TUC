#ifndef __SIMPLE_CRYPTO_H
#define __SIMPLE_CRYPTO_H

char* inputString(FILE* fp, size_t size);

void randomKeyGenerator(int size);
char* otpEncrypt(char* text);
char* otpDecrypt(char* text);
void oneTimePad();

char* caesarEncrypt(char* text, int k);
char* caesarDecrypt(char* text, int k);
void caesar();

char* generateKey(char* key, int length);
char* vigenereEncrypt(char* text, char* key);
char* vigenereDecrypt(char* text, char* key);
void vigenere();

#endif