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
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
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

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, argv[2]);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	fclose(log);
	//argc -= optind;
	//argv += optind;	
	
	return 0;
}
