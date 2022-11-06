
Assignment 6

------------  HOW TO RUN THIS PROGRAM --------------
1) make clean
2) make 
3) ./monitor -r <filename>	     


***** monitor *****
--Packet capture --> ./monitor -r <filename>
--Help message   --> ./monitor -h 

****** clean *********
--> make clean
Deletes all the files that were created after make or files for testing.

Answers and Implementation:
* filename --> test_pcap_5mins.pcap

a. Total number of network flows captured: 1205
b. Number of TCP network flows captured: 941
c. Number of UDP network flows captured: 264
d. Total number of packets received: 14261
e. Total number of TCP packets received: 13708
f. Total number of UDP packets received: 501
g. Total bytes of TCP packets received: 9135182
h. Total bytes of UDP packets received: 75353

9) Can you tell if an incoming TCP packet is a retransmission? If yes, how? If not, why?

    TCP packets contain information about the sequence number and ACKnowledgement number. Using
    those numbers, we could see the communication between the sender and the receiver. Client initiates 
    the connection and sends the segment with a Sequence number. Server acknowledges it back with its own 
    Sequence number and ACK of client’s segment which is one more than client’s Sequence number. Client after 
    receiving ACK of its segment sends an acknowledgement of Server’s response. On my code, I tried to 
    check if a packet is retransmitted, by creating three functions: check_retransmission(), 
    add_transmission(), add_to_current_flow(). The idea behind these functions is to check if 
    the sequence number, acknowledgement number etc are all in order on the same network flow.

10) Can you tell if an incoming UDP packet is a retransmission? If yes, how? If not, why? 
 
    We cannot tell if a UDP packet is retransmitted, because this protocol does not support this functionality 
    and all the information needed.


Useful Links:
https://linux.die.net/man/3/pcap
https://www.tcpdump.org/index.html#source
https://www.tutorialspoint.com/data_communication_computer_network/transmission_control_protocol.htm


gcc version: gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0




