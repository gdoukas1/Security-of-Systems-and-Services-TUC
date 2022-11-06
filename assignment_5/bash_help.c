#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>


int main(int argc, char *argv[]){
    size_t bytes;
    FILE *file;
    
    if (argc<2){
        printf("Error! Arguments must be at least two\n");
        return 1;
    }

    char* dir = argv[1];
    int num = atoi(argv[2]);
    
    //char* dir = "/test_dir/";
    //int num =  100;


    //creation of important files
    for (int i = 1 ; i<=num; i++){

        char resolved_path[1024] = {0};
        char no[4] = {0};
        //contents
        char str[100] = "File to be encrypted No.";
        sprintf(no, "%d", i);
        strcat(str, no);
        
        //path
        realpath(dir, resolved_path);
        strcat(resolved_path, "/file_");
        strcat(resolved_path, no);
        strcat(resolved_path, ".txt");

        file = fopen(resolved_path, "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			fwrite(str, strlen(str), 1, file);
			fclose(file);
		} 
    }

    for (int i = 1 ; i<= num; i++){
        char junk_path[1024] = {0};
        char no[4] = {0};
        //contents
        char str[100] = "Junk File - No.";
        sprintf(no, "%d", i);
        strcat(str,no);

        //path
        realpath(dir, junk_path);
        strcat(junk_path, "/junk_");
        strcat(junk_path, no);
        strcat(junk_path, ".junk");

        file = fopen(junk_path, "w+");
        if (file == NULL) 
            printf("fopen error\n");
        else {
            fwrite(str, strlen(str), 1, file);
            fclose(file);
	    } 
    }

    return 0;

}