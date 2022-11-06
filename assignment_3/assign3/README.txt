COMMANDS

*compile --> make

*step 1 --> make run

*step 2:
--Print malicious users  --> ./acmonitor -m
--Prints table of users that modified the file given, and the number of
modifications --> ./acmonitor -i <filename>
--Help message  --> ./acmonitor -h 

*clean --> make clean
Deletes all the files that were created after "make run".

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


gcc version: gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0