Assignment 5

------------  HOW TO RUN THIS PROGRAM --------------
1) make
2) make run 
3) ./ransomware.sh -p <dir> -n <number of files to be created> 
4) ./ransomware.sh -e <dir> 
5) ./ransomware.sh -d <dir> 
6) ./acmonitor -m 	   
7) ./acmonitor -i <filename>  
8) ./acmonitor -v <number of files>
9) ./acmonitor -e

Note: step 2 is unnecessary, because the files are created at ransomware.

***** Ransomware *****
1)  ./ransomware.sh -p <dir> -n <number of files to be created> 

Creates N files file_N.txt that are important for the user and will be encrypted and also 
creates N junk files junk_N.junk that are the big volume of files, in the directory <dir> 
that is given as an argument
 
2) ./ransomware.sh -e <dir> 
Encrypts all the files in the specified directory

3) ./ransomware.sh -d <dir> 
Decrypts all the files in the specified diractory


***** acmonitor *****
--Print malicious users  --> ./acmonitor -m
--Prints table of users that modified the file given, and the number of
modifications --> ./acmonitor -i <filename>
--Prints the total number of files created in the last 20 minutes. 
Comparing with <number of files> we detect suspicious activity --> ./acmonitor -v <number of files>
--Prints all the files that were encrypted by the ransomware --> ./acmonitor -e
--Help message  --> ./acmonitor -h 

****** clean *********
--> make clean
Deletes all the files that were created after make or files for testing.

Implementation:
Whenever a user creates, modifies, or access a file with the funtions fopen() and fwrite(), 
the event is saved in a log file (file_logging.log). Then each event of the log file is stored in a linked list
so we can access the stored data more easily.
If we want to print the malicious users first we create a hash table with buckets. And then we store in a linked list 
to each bucket that specifies a particular user all the files that tried to access without permission. Finally we count 
how many files there are in each bucket and print the user id and the number of files.
If we want to print the number of modifications from the users for a specific file we create a hash table that stores 
in each cell a user id and the number of modifications that made that user to the specific file.
Function fwrite() has not implemented properly.


Useful Links:
https://www.gnu.org/software/libc/manual/html_node/Testing-File-Access.html
https://www.openssl.org/docs/manmaster/man3/MD5_Init.html
https://pubs.opengroup.org/onlinepubs/007904975/functions/fopen.html
https://stackoverflow.com/questions/1442116/how-to-get-the-date-and-time-values-in-a-c-program
https://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
https://www.educative.io/edpresso/splitting-a-string-using-strtok-in-c
http://osr507doc.sco.com/en/man/html.S/chmod.S.html
https://stackoverflow.com/questions/1188757/retrieve-filename-from-file-descriptor-in-c
https://www.geeksforgeeks.org/shift-command-in-linux-with-examples/
https://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c
https://linux.die.net/man/1/openssl
https://wiki.openssl.org/index.php/Command_Line_Utilities



gcc version: gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0