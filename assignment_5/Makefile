all: logger acmonitor test_aclog bash_help
	touch file_logging.log

logger: logger.c
	gcc -Wall -fPIC -shared -g -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -g -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -g -o test_aclog

bash_help: bash_help.c
	gcc bash_help.c -g -o bash_help
	
run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf bash_help
	rm -rf file_*

