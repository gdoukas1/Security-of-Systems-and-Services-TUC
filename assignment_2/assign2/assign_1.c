#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
unsigned char *keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
unsigned char *
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{ /* Task A */
	const EVP_CIPHER *cipher = NULL;
	const EVP_MD *md = NULL;


	if (bit_mode==128){
		printf ("Creating the %d bit key...\n", bit_mode);
		cipher = EVP_get_cipherbyname("aes-128-ecb");

	}
	else if(bit_mode==256){
		printf ("Creating the %d bit key...\n", bit_mode);
		cipher = EVP_get_cipherbyname("aes-256-ecb");
	}
	else{
		exit(EXIT_FAILURE);
    }

	md = EVP_get_digestbyname("sha1");

	key = malloc(EVP_CIPHER_key_length(cipher) * sizeof(char));
	iv = malloc(EVP_CIPHER_iv_length(cipher) * sizeof(char));
	
	EVP_BytesToKey(cipher, md, NULL, password, strlen((char*)password), 1, key, iv);

	print_hex(key, EVP_CIPHER_key_length(cipher));
	//print_hex(iv, EVP_CIPHER_iv_length(cipher));
	return key;
}


/*
 * Encrypts the data
 */
void
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{/* TODO Task B */
	EVP_CIPHER_CTX *ctx;
	int len, ciphertext_len;

	 /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
	if(!ctx){
		printf("Failed at context new\n");
		exit(EXIT_FAILURE);
	}

	if(bit_mode == 128)
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
	else if(bit_mode == 256)
		EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
	else
		exit(EXIT_FAILURE);

	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
	ciphertext_len = len;

	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;

	printf("Encrypted text:\n");
	print_hex(ciphertext, ciphertext_len);
	//EVP_CIPHER_CTX_free(ctx);
}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_len, len;

	plaintext_len = 0;

	/*TODO Task C */
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();

	if(!ctx){
		printf("Failed at context new\n");
		exit(EXIT_FAILURE);
	}

	if(bit_mode == 128)
		EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
	else if(bit_mode == 256)
		EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
	else
		exit(EXIT_FAILURE);

	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	plaintext_len += len;

	printf("Decrypted text:\n");
	print_string(plaintext, plaintext_len);
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{/* TODO Task D */
	CMAC_CTX *ctx = CMAC_CTX_new();
	size_t cmac_len = bit_mode/8;
	
	if(bit_mode == 128)
		CMAC_Init(ctx, key, cmac_len, EVP_aes_128_ecb(), NULL);
	else if(bit_mode == 256)
		CMAC_Init(ctx, key, cmac_len, EVP_aes_256_ecb(), NULL);
	else
		exit(EXIT_FAILURE);
	
	CMAC_Update(ctx, data, data_len);
	CMAC_Final(ctx, cmac, &cmac_len);
	
	printf("cmac: \n");
	print_hex(cmac, BLOCK_SIZE);
	
	CMAC_CTX_free(ctx);
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0; //TRUE

	/* TODO Task E */
	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		if (cmac1[i] != cmac2[i]){
			verify = 1;  //FALSE
		}
	}

	return verify;
}



/* TODO Develop your functions here... */


/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */
	unsigned char *key = NULL;
	unsigned char *iv = NULL;
	unsigned char *plaintext = NULL;
	unsigned char *ciphertext = NULL;
	unsigned char *cmac = NULL;

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */

	/* Initialize the library */
	OpenSSL_add_all_algorithms();

	/* Keygen from password */
	key = keygen(password, key, iv, bit_mode);

	/* Operate on the data according to the mode */
	/* encrypt */
	if(op_mode==0){
		FILE *fp = fopen(input_file, "rb");
	
		if(fp == NULL){
			printf("This file doesn't exist");
			exit(EXIT_FAILURE);
		}
	 	// calculating the size of the file
		fseek(fp, 0L, SEEK_END);  //It moves file pointer position to the end of file.
		int numberOfBytes = ftell(fp);
		plaintext = malloc(sizeof(char) * numberOfBytes);
		fseek(fp, 0L, SEEK_SET); // It moves file pointer position to the beginning of the file.
		fread(plaintext, sizeof(char), numberOfBytes, fp);
		
		ciphertext = malloc(numberOfBytes * sizeof(char));
		encrypt(plaintext, numberOfBytes, key, iv, ciphertext, bit_mode);
		
		FILE *out_fp = fopen(output_file, "wb");
		int ciphertext_length = numberOfBytes/BLOCK_SIZE;
		ciphertext_length = ciphertext_length*BLOCK_SIZE +BLOCK_SIZE; 
		fwrite(ciphertext, sizeof(char), ciphertext_length, out_fp);
		
		free(plaintext);
		free(ciphertext);
		fclose(fp);
		fclose(out_fp);
	}

	/* decrypt */
	else if(op_mode==1){
		FILE *fp = fopen(input_file, "rb");
	
		if(fp == NULL){
			printf("This file doesn't exist");
			exit(EXIT_FAILURE);
		}
	 	// calculating the size of the file
		fseek(fp, 0L, SEEK_END);  //It moves file pointer position to the end of file.
		int numberOfBytes = ftell(fp);
		ciphertext = malloc(sizeof(char) * numberOfBytes);
		fseek(fp, 0L, SEEK_SET); // It moves file pointer position to the beginning of the file.
		fread(ciphertext, sizeof(char), numberOfBytes, fp);
		
		plaintext = malloc(numberOfBytes * sizeof(char));
		int plaintext_len = decrypt(ciphertext, numberOfBytes, key, iv, plaintext, bit_mode);

		FILE *out_fp = fopen(output_file, "wb");
		fwrite(plaintext, sizeof(char), plaintext_len, out_fp);
		
		free(plaintext);
		free(ciphertext);
		fclose(fp);
		fclose(out_fp);
	}

	/* sign */
	else if(op_mode==2){
		FILE *fp = fopen(input_file, "rb");
	
		if(fp == NULL){
			printf("This file doesn't exist");
			exit(EXIT_FAILURE);
		}
	 	// calculating the size of the file
		fseek(fp, 0L, SEEK_END);  //It moves file pointer position to the end of file.
		int numberOfBytes = ftell(fp);
		plaintext = malloc(sizeof(char) * numberOfBytes);
		fseek(fp, 0L, SEEK_SET); // It moves file pointer position to the beginning of the file.
		fread(plaintext, sizeof(char), numberOfBytes, fp);
		
		ciphertext = malloc(numberOfBytes * sizeof(char));
		encrypt(plaintext, numberOfBytes, key, iv, ciphertext, bit_mode);
		
		cmac = malloc(BLOCK_SIZE * sizeof(char));
		gen_cmac(plaintext, numberOfBytes, key, cmac, bit_mode);
		
		FILE *out_fp = fopen(output_file, "wb");
		int ciphertext_length = numberOfBytes/BLOCK_SIZE;
		ciphertext_length = ciphertext_length*BLOCK_SIZE +BLOCK_SIZE; 
		fwrite(ciphertext, sizeof(char), ciphertext_length, out_fp);
		fwrite(cmac, sizeof(char), BLOCK_SIZE, out_fp);
		
		free(plaintext);
		free(ciphertext);
		fclose(fp);
		fclose(out_fp);
	}
	
	/* verify */
	else if(op_mode==3){
		FILE *fp = fopen(input_file, "rb");
	
		if(fp == NULL){
			printf("This file doesn't exist");
			exit(EXIT_FAILURE);
		}
	 	// calculating the size of the file
		fseek(fp, 0L, SEEK_END);  //It moves file pointer position to the end of file.
		long int numberOfBytes = ftell(fp);

		unsigned char *cipherCMAC = malloc(sizeof(char) * numberOfBytes);

		fseek(fp, 0L, SEEK_SET); // It moves file pointer position to the beginning of the file.

		fread(cipherCMAC, sizeof(char), numberOfBytes, fp);
	
		
		plaintext = malloc(numberOfBytes * sizeof(char));
		int plaintext_length = decrypt(cipherCMAC, numberOfBytes, key, iv, plaintext, bit_mode);
		
		fseek(fp, -16, SEEK_END);
		//printf("fp = %ld\n", ftell(fp));
		fread(cipherCMAC, sizeof(char), BLOCK_SIZE, fp);
		printf("cipherCMAC: \n");
		print_hex(cipherCMAC,BLOCK_SIZE);

		cmac = malloc (BLOCK_SIZE * sizeof(char));
        gen_cmac(plaintext, plaintext_length, key, cmac, bit_mode);
		
		
		if(verify_cmac(cipherCMAC, cmac) == 0){
			printf("Verified\n");
			FILE *out_fp = fopen(output_file, "wb");

			fwrite(plaintext, sizeof(char), plaintext_length, out_fp);
		
			fclose(out_fp);
			}
		else
			printf("Not verified\n");
		

		free(plaintext);
		free(cipherCMAC);
		free(cmac);
		fclose(fp);
	}

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
