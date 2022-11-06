#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <errno.h>

#define LOGFILE "file_logging.log"


unsigned char* md5HashGenerator(const char* path){
	unsigned char *digest = (unsigned char*) malloc(MD5_DIGEST_LENGTH);
	MD5_CTX context;
	int bytes;
	int buffersize = 512;
	unsigned char buffer[buffersize];

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, "rb");
	
	if(original_fopen_ret == NULL){
		printf("ERROR. %s can't be opened\n", path);
		free(digest);
		return NULL;
	}

	MD5_Init(&context);
	while((bytes = fread(buffer,1,buffersize,original_fopen_ret))!= 0){
		MD5_Update(&context, buffer, bytes);
	}
	MD5_Final(digest, &context);

	return digest;
}


void 
writeLogEntries(const char *path, int accessType, int actionFlag){
	uid_t uid = getuid();
	time_t t = time(NULL);
  	struct tm tm = *localtime(&t);

	char* actualPath = realpath(path, NULL);
	unsigned char* hash = md5HashGenerator(path);

	FILE *logfile;
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	logfile = (*original_fopen)(LOGFILE, "a");
    
	fprintf(logfile,"%u %s %s %02d-%02d-%d %02d:%02d:%02d %d %d ", 
	uid, actualPath, path, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, accessType, actionFlag);
	
	
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) fprintf(logfile, "%02x", hash[i]);
	fprintf(logfile, "\n");
			
	fclose(logfile);
}



FILE *
fopen(const char *path, const char *mode) 
{
	int accessType, actionFlag;
	accessType = 0;
	actionFlag = 0;


	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	
	if(access(path, F_OK) == -1)
		accessType = 0;
	else if(strcmp(mode,"r")==0 || strcmp(mode,"r+")==0 || strcmp(mode,"rb")== 0)
		accessType = 1;
	else if(strcmp(mode,"w")==0 || strcmp(mode,"w+")==0 || strcmp(mode,"wb")==0 || strcmp(mode,"a")==0 || strcmp(mode,"a+")==0)
		accessType = 2;
	else
		accessType = 1;
	

	 if (original_fopen_ret == NULL){
        printf("errno: %d\n", errno);
        if (errno == EACCES || errno == EPERM){
           actionFlag = 1;
        }
	 }
    else{
		actionFlag = 0;
	}

	writeLogEntries(path, accessType, actionFlag);
	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	
	/*
	int BUFFERSIZE = 50;
	char *filename = (char*) malloc(BUFFERSIZE* sizeof(char));
	int fno = fileno(stream);
	char proc[BUFFERSIZE];
	sprintf(proc, "/proc/self/fd/%d", fno);
	ssize_t r = readlink(proc, filename, BUFFERSIZE);

	if(r < 0){
		printf("Failed at readlink\n");
	}

	filename[r+1] = '\0';
	
	if(original_fwrite_ret == nmemb)
		writeLogEntries(filename, 2, 0);
	else
		writeLogEntries(filename, 2, 1);
	
	free(filename);
	*/
	return original_fwrite_ret;
}


