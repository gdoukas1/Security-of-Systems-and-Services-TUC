#include "rsa.h"
#include "utils.h"
#include <math.h>
#include <stdio.h>

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
	size_t *arr = malloc((limit+1)*sizeof(size_t));
	int i = 0;
	int j = 0;
	int primes_size = limit-1;

	//initialization
	for(i=0; i<limit+1; i++){
		arr[i] = i;
	}
	//implementation
	for(i=2; i<limit+1;i++){
		if(arr[i]!=0){
			for(j=2;j<limit+1;j++ ){
				if (j%i ==0 && i!=j && arr[j]!=0){
					arr[j] = 0;
					primes_size--;
				}
			}
		}
	}

	size_t *primes = malloc((primes_size)*sizeof(size_t));
	j=0;
	for(i=2;i<=limit;i++){
		if(arr[i]!=0){
			primes[j] = arr[i];
			j++;
		}
	}
	*primes_sz = primes_size;

	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{

// Everything divides 0
    if (a == 0)
       return b;
    if (b == 0)
       return a;
 
    // base case
    if (a == b)
        return a;
 
    // a is greater
    if (a > b)
        return gcd(a-b, b);
    return gcd(a, b-a);
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n, size_t *primes)
{
	size_t e;
	e = primes[rand()%sizeof(primes)];
	while(!((e%fi_n!=0)&&(gcd(e,fi_n)==1)))
		e = primes[rand()%sizeof(primes)];

	return e;
}

size_t gcdExtended(size_t a, size_t b, size_t* x, size_t* y)
{
    // Base Case
    if (a == 0)
    {
        *x = 0; 
		*y = 1;
        return b;
    }
 
	size_t x1, y1; // To store results of recursive call
    size_t gcd_result = gcdExtended(b % a, a, &x1, &y1);
 
    // Update x and y using results of recursive
    // call
    *x = y1 - (b / a) * x1;
    *y = x1;
 
    return gcd_result;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{	size_t res = 0;
	size_t x, y;
    size_t g = gcdExtended(a, b, &x, &y);
    if (g != 1)
        printf("Inverse doesn't exist");
    else
    {
        // b is added to handle negative x
        res = (x % b + b) % b;
        //printf("Modular multiplicative inverse is %d", res);
    }
	return res;
}

/**
 * @brief 
 * (m^e) mod n
 * @param m 
 * @param e 
 * @param n 
 * @return long long 
 */
long long mod_exp(long long m, long long e, long long n)
{
    int res = 1;     // Initialize result
 
    m = m % n; // Update m if it is more than or
                // equal to n
  
    if (m == 0) 
		return 0; // In case m is divisible by n;
 
    while (e > 0)
    {
        // If e is odd, multiply m with result
        if (e & 1)
            res = (res*m) % n;
 
        // e must be even now
        e = e/2;
        m = (m*m) % n;
    }
    return res;
}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;
	int *prime_sz = malloc(sizeof(int));

	size_t *primes_arr = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, prime_sz); 
	int p_size = *prime_sz;
	
	p = primes_arr[rand()% p_size];
	q = primes_arr[rand()% p_size];
	n = p*q;
	fi_n = (p-1)*(q-1);
	e = choose_e(fi_n, primes_arr);
	d = mod_inverse(e,fi_n);

	FILE *keyPublic = fopen("public.key","wb");
	fwrite(&n, sizeof(size_t), 1, keyPublic);
	fwrite(&d, sizeof(size_t), 1, keyPublic);
	fclose(keyPublic);

	FILE *keyPrivate = fopen("private.key","wb");
	fwrite(&n, sizeof(size_t), 1, keyPrivate);
	fwrite(&e, sizeof(size_t), 1, keyPrivate);
	fclose(keyPrivate);
}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
	char *plaintext;
	size_t *ciphertext;

	FILE *fp = fopen(input_file, "rb");
	FILE *keyFp = fopen(key_file, "rb");

	if(fp == NULL || keyFp == NULL){
		printf("This file doesn't exist");
		exit(EXIT_FAILURE);
	}

	// calculating the size of the file
	fseek(fp, 0L, SEEK_END);  //It moves file pointer position to the end of file.
	int numberOfBytes = ftell(fp);
	
	plaintext = malloc(sizeof(char) * numberOfBytes);
	fseek(fp, 0L, SEEK_SET); // It moves file pointer position to the beginning of the file.
	
	size_t n,d;
	fread(&n, sizeof(size_t), 1, keyFp);
	fread(&d, sizeof(size_t), 1, keyFp);

	size_t plaintext_len = fread(plaintext, sizeof(char), numberOfBytes, fp);
	
	ciphertext = malloc(numberOfBytes * sizeof(size_t));
	for(int i=0; i<plaintext_len; i++){
		ciphertext[i] = mod_exp(plaintext[i],(long long)d, (long long)n);
	}

	FILE *out_fp = fopen(output_file, "wb"); 
	fwrite(ciphertext, sizeof(size_t), numberOfBytes, out_fp);
	
	free(plaintext);
	free(ciphertext);
	fclose(fp);
	fclose(out_fp);
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{
	char *plaintext;
	size_t *ciphertext;

	FILE *fp = fopen(input_file, "rb");
	FILE *keyFp = fopen(key_file, "rb");

	if(fp == NULL || keyFp == NULL){
		printf("This file doesn't exist");
		exit(EXIT_FAILURE);
	}

	// calculating the size of the file
	fseek(fp, 0L, SEEK_END);  //It moves file pointer position to the end of file.
	int numberOfBytes = ftell(fp);
	
	ciphertext = malloc(sizeof(char) * numberOfBytes);
	fseek(fp, 0L, SEEK_SET); // It moves file pointer position to the beginning of the file.
	
	size_t n,e;
	fread(&n, sizeof(size_t), 1, keyFp);
	fread(&e, sizeof(size_t), 1, keyFp);

	size_t ciphertext_len = fread(ciphertext, sizeof(char), numberOfBytes, fp);
	
	plaintext = malloc(numberOfBytes * sizeof(char));
	for(int i=0; i<ciphertext_len; i++){
		plaintext[i] = mod_exp(ciphertext[i],(long long)e, (long long)n);
	}

	FILE *out_fp = fopen(output_file, "wb");
	numberOfBytes = numberOfBytes/8; 
	fwrite(plaintext, sizeof(char), numberOfBytes, out_fp);
	
	free(plaintext);
	free(ciphertext);
	fclose(fp);
	fclose(out_fp);

}
