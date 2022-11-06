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
	long buffersize;

	FILE *fd;
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	fd = (*original_fopen)(path, "rb");
	
	if(fd == NULL){
		printf("ERROR. %s can't be opened\n", path);
		free(digest);
		return NULL;
	}

	fseek(fd,0,SEEK_END);
	buffersize = ftell(fd);
	fseek(fd,0,SEEK_SET);
	unsigned char buffer[buffersize];
	
	MD5_Init(&context);

	while((bytes = fread(buffer,1,buffersize,fd))!= 0){
		MD5_Update(&context, buffer, bytes);
	}
	
	MD5_Final(digest, &context);
	fclose(fd);

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

	if(logfile==NULL) 
		printf("LOGFILE IS NULL\n");
    
	fprintf(logfile,"%u %s %02d-%02d-%d %02d:%02d:%02d %d %d ", 
	uid, actualPath, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, accessType, actionFlag);
	
	if(hash != NULL){
		for (int i = 0; i < MD5_DIGEST_LENGTH; i++) 
			fprintf(logfile, "%02x", hash[i]);
		free(hash);
	}
	else{
		for (int i = 0; i < MD5_DIGEST_LENGTH; i++) 
			fprintf(logfile, "%02x", 0);
	}

    fprintf(logfile, "\n");
	fclose(logfile);
}

char* getFilePath(int fno) {
    int BUFFERSIZE = 0xFFF;
    char proc[BUFFERSIZE];
    char *filename = (char*) malloc(BUFFERSIZE);
    ssize_t r;

    sprintf(proc, "/proc/self/fd/%d", fno);

    r = readlink(proc, filename, BUFFERSIZE);

    if (r < 0) {
        printf("Failed at readlink\n");
        filename = " ";
        return filename;
    }
    filename[r] = '\0';
    return filename;
}

FILE *
fopen(const char *path, const char *mode) 
{
	int accessType, actionFlag;
	accessType = 0;
	actionFlag = 0;

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	if(access(path, F_OK) == 0) 
		accessType = 1;		//file exists
	else
		accessType = 0;     //file doesn't exist. Creation of file

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);	

	if (original_fopen_ret == NULL){
        //printf("errno: %d\n", errno);
        if (errno == EACCES || errno == EPERM){
           actionFlag = 1;
        }
	} 

	writeLogEntries(path, accessType, actionFlag);
	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{	
	int actionFlag = 0;
	int accessType = 2;
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	
	fflush(stream);
	char* path = getFilePath(fileno(stream));
	
	if(access(path,W_OK) == 0)
		actionFlag = 0;		//permission accepted
	else
		actionFlag = 1;     //permission denied
	
	writeLogEntries(path, accessType, actionFlag);
	free(path);
	return original_fwrite_ret;
}


