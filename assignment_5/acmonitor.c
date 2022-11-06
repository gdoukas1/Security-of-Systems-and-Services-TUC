#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SIZE 10000

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char *date; /* file access date */
	char *time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	struct entry *next;
};

struct DataItem{
	int userId;
	char* data;
	struct DataItem *next;
};

struct DataItem *hashTable[SIZE];


void insertFile(int key,char* filename) {
	struct DataItem *item = (struct DataItem*) malloc(sizeof(struct DataItem));
   	item->userId = key;  
   	item->data = filename;

	struct DataItem *tmp = hashTable[key];
   	while(tmp->next != NULL){
	   	if(strcmp(tmp->data,item->data)==0)
	   		return;
		else{
			tmp = tmp->next;
		}
   }

   tmp->next = item;
   return;
}

void insert(int key, int times) {
	struct DataItem *item = (struct DataItem*) malloc(sizeof(struct DataItem));
   	item->userId = key;  
   	//item->data = (char*) times;
	sprintf(item->data, "%d", times);
	
	hashTable[key] = item;
	return;
}


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./acmonitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		    "-v <number of files>, Prints the total number of files created in the "
           "last 20 minutes. Comparing with <number of files> we detect suspicious activity\n"
		    "-e, Prints all the files that were encrypted by the ransomware\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

void
list_Init(FILE *log, struct entry **listOfEntries){
	char *line;
	size_t length = 0;
	size_t characters = -1;
	struct entry *last = *listOfEntries;
	

	while (characters = getline(&line, &length, log) != 0){
		struct entry *newNode = (struct entry*) malloc(sizeof(struct entry));

		newNode->uid = atoi(strtok(line," "));
		strtok(NULL, " ");
		newNode->file = strtok(NULL," ");
		newNode->date = strtok(NULL," ");
		newNode->time = strtok(NULL," ");
		newNode->access_type = atoi(strtok(NULL," "));
		newNode->action_denied = atoi(strtok(NULL," "));
		newNode->fingerprint = strtok(NULL," ");
		newNode->next = NULL;


		if(*listOfEntries == NULL){
			*listOfEntries = newNode;
		}

		while (last->next != NULL)
		{
			last = last->next;
		}

		last->next = newNode;
	}
	return;
}



void 
list_unauthorized_accesses(FILE *log)
{
	int unauthorizedCounter=0;
	struct DataItem *item;

	struct entry *userList = NULL;
	list_Init(log, &userList);

	while (userList != NULL){
		if(userList->action_denied == 1){
			item = hashTable[userList->uid];
			if (item!=NULL)
			{	
				insertFile(userList->uid, userList->file);
			}
		}
		userList = userList->next;
	}

	for(int i =0; i<SIZE; i++){
		if(hashTable[i] != NULL){
			struct DataItem *temp = hashTable[i];
			while(temp->next != NULL){
				unauthorizedCounter++;
				temp = temp->next;
			}
			if(unauthorizedCounter > 7)
				printf("Malicious user: %d tried to access %d files without permission\n",hashTable[i]->userId, unauthorizedCounter);
		}
		unauthorizedCounter = 0;
	}
	
	return;
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{	
	int modificationCounter = 0;
	char *fingerprint = NULL;
	struct DataItem *item;
	struct entry *userList = NULL;
	list_Init(log, &userList);

	

	while (userList != NULL){
		if(strcmp(userList->file, file_to_scan) == 0){
			item = hashTable[userList->uid];
			
			if ((userList->access_type == 0) && (userList->action_denied == 0))
				fingerprint = userList->fingerprint;
			if (((userList->access_type == 1) || (userList->access_type == 2)) && (userList->action_denied == 0)){	
				if(item!=NULL){
					if(strcmp(fingerprint, userList->fingerprint) == 0){
						modificationCounter = atoi(item->data) +1;
						insert(userList->uid, modificationCounter);
					}
				}
			}
		}
		userList = userList->next;
	}

	for(int i =0; i<SIZE; i++){
		if(hashTable[i] != NULL){
			printf("Modified by user: %d ,  %s times\n",hashTable[i]->userId, hashTable[i]->data);
		}
	}
	return;

}

int s_ends_with(const char *s, const char *suffix) {
    int  ret_val = 0;
	size_t slen = strlen(s);
    size_t suffix_len = strlen(suffix);
	const char *p = s + slen - suffix_len;
    if (suffix_len <= slen && !strcmp(s + slen - suffix_len, suffix)){
		ret_val = 1;
	}
	return ret_val;
}

void
list_encrypted_files(FILE* log){
	struct DataItem *item;
	struct entry *userList = NULL;
	list_Init(log, &userList);
	char file_enc[500][1024]={0};
	int pos = 0;

	while (userList != NULL){
		 if(strstr(userList->file,".encrypt")!=NULL && userList->access_type==0 ){
			 if (s_ends_with(userList->file,".encrypt")==1){
                printf("%s has been encrypted\n",userList->file);
			}
		}
		userList = userList->next;
	}
	return;
}

void
list_recent20min_modifications(FILE* log, int num){
    struct DataItem *item;
	struct entry *userList = NULL;
	list_Init(log, &userList);
	
	
	int counter = 0;
	time_t now= time(NULL);
    struct tm tm = *localtime(&now);
	int minutes;
	int day, month, year, hour, min, sec;
	struct tm * tm_file = (struct tm *)malloc(sizeof(struct tm));

	while (userList != NULL){
		char *date_of_file = userList->date;
		char *time_file = userList->time;
		year = atoi(strtok(date_of_file, "-"));
		month = atoi(strtok(NULL, "-"));
		day = atoi(strtok(NULL, "-"));
		hour = atoi(strtok(time_file, ":"));
		min = atoi(strtok(NULL, ":"));
		sec = atoi(strtok(NULL, ":"));

		if(userList->access_type==0 && userList->action_denied == 0){
			
			tm_file->tm_sec   = sec;
			tm_file->tm_min   = min;
			tm_file->tm_hour  = hour;
            tm_file->tm_mday  = day;
			tm_file->tm_mon   = month - 1;
			tm_file->tm_year  = year - 1900;
		}

		time_t t_file = mktime(tm_file);
		time_t current = mktime(&tm);
		minutes = (difftime(now,t_file))/60;  // in minutes

		if (minutes<=20 ){
				counter++;
		}
		userList = userList->next;
    }
     
    
    if(counter >= num){
        printf("\nWARNING! %d files are created in the last 20 minutes.\n",counter);
    }
    else
        printf("\nNo problem detected! %d files are created in the last 20 minutes\n",counter);
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "himev")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, argv[2]);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'e':
			list_encrypted_files(log);
			break;
		case 'v':
			list_recent20min_modifications(log, atoi(argv[2]));
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	return 0;
}
