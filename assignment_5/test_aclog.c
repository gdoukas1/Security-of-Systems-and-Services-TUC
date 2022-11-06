#define _POSIX_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	//write to file_0 multiple times
	file = fopen(filenames[0], "w+");
	char strings_to_write[2][10]={"Hello ","World!"};
	for (i = 0; i < 2; i++)
	{
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(strings_to_write[i],1,strlen(strings_to_write[i]), file);
		}
	}
	fclose(file);
	
	//malicious user. too many attempts without privileges
	for (i = 0; i < 10; i++) {
		chmod(filenames[i], 0);
		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			fclose(file);
		}	
	}
	
}
