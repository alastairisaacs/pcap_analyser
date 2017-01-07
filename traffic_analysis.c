#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "packet_header_func.h"

// Defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

// Output file defintions
FILE *f_ip_len;     // IPLenAnalysis.csv
FILE *f_protocol;   // ProtocolAnalysis.csv
FILE *f_tcp_port;   // TCPPortAnalysis.csv
FILE *f_udp_port;   // UDPPortAnalysis.csv
FILE *f_udp_len;    // UDPLenAnalysis.csv
FILE *f_tcp_len;    // TCPLenAnalysis.csv
FILE *f_err;	    // ErrorLog.txt

// The program begins...

int main(int argc, char **argv)          // allows multiple input files
{
 // Define variables
 char command[800];
 int fnum;			         // File number
 int i;					 // Loop index
 unsigned long pkt_counter=0;            // Number of packets seen
 unsigned long user_pkt_counter=0;       // Number of user data packets analysed
 unsigned long user_total_volume=0;      // Total volume of user data in bytes
 unsigned long tcp_total_volume = 0;	 
 unsigned long udp_total_volume = 0;
 unsigned long udp_counter = 0;
 
 int ether_offset;		// Length of ethernet header
 int ip_offset;			// Length of inner IP header
 int udp_len;			// Length of inner UDP packet payload
 int tcp_hdr_len;		// Length of inner TCP header
 int tcp_length;		// Length of inner TCP packet payload

 int port; 		        // 0 if should look at source port, 1 is destination port
 int *pnt_port = &port;
 int ip_protocol;		// Stores value of next protocol field in inner IP header
 int *pnt_ip_protocol = &ip_protocol;
 int ip_length;                 // Stores length of inner IP header
 int *pnt_ip_length = &ip_length;
 int port_number;               // Stores inner UDP/TCP source/destination port
 int *pnt_port_number = &port_number;
 int tcp_flags;			// Stores value of TCP flags field (whole byte)
 int *pnt_tcp_flags = &tcp_flags;


 unsigned long arr_iplength[65536] = {0};                    
// Array to store ip lengths- row number is (packet length - 1), value stored is number of packets with that length

 unsigned long arr_protocol[256][3] = {0};
// Array to store next header protocols.Row number is protocol ID, 1st column is number of bytes, 2nd column is background bytes, 3rd column is streaming bytes  

 unsigned long arr_tcp_port[65536] = {0};
// Array to store TCP ports.Row number is port number, value stored is number of bytes.

 unsigned long arr_tcp_len[65536] = {0};
// Array to store TCP lengths. Row number is payload length, value stored is number of packets

 unsigned long arr_udp_port[65536] = {0};
// Array to store UDP ports.Row number is port number, value stored is number of bytes.

 unsigned long arr_udp_len[65536] = {0};
// Array to store udp lengths - row number is payload length, value stored is number of packets

//Counters for types of TCP packet
 unsigned long tcp_counter = 0;
 unsigned long syn_counter = 0;
 unsigned long syn_ack_counter = 0;
 unsigned long fin_counter = 0;
 unsigned long fin_ack_counter = 0;
 unsigned long syn_fin_counter = 0;
 unsigned long syn_rst_counter = 0;
 unsigned long fin_rst_counter = 0;
 unsigned long pure_ack_counter = 0;
 unsigned long data_counter = 0;
 unsigned long reset_counter = 0;
 unsigned long weird_counter = 0;

// Output files
 f_ip_len = fopen ("IPLenAnalysis.csv", "wt");
 f_protocol = fopen ("ProtocolAnalysis.csv", "wt");
 f_tcp_port = fopen ("TCPPortAnalysis.csv", "wt");
 f_tcp_len = fopen ("TCPLenAnalysis.csv", "wt");
 f_udp_port = fopen ("UDPPortAnalysis.csv", "wt");
 f_udp_len = fopen ("UDPLenAnalysis.csv", "wt");
 f_err = fopen ("ErrorLog.txt", "wt");
 

 // Create temporary packet buffers
 struct pcap_pkthdr header;              // The header that pcap gives us 
 const u_char *packet;                   // The actual packet  
 
 // Check command line arguments 
 if (argc < 2) 
 { 
   fprintf(stderr, "Usage: %s [.cap filename]\n", argv[0]); 
   exit(1); 
 } 

 // Begin by processing the files

 for (fnum=1; fnum < argc; fnum++) 
 {  
   // Loop through the .cap files in the order given when called
   sprintf(command, "zcat %s > tempfile", argv[fnum]);
   system(command);
   pcap_t *handle; 
   char errbuf[PCAP_ERRBUF_SIZE]; 
   //handle = pcap_open_offline(argv[fnum], errbuf);  // Call pcap library function 
   handle = pcap_open_offline("tempfile", errbuf);  // Call pcap library function 
 
   if (handle == NULL)                              // If there is a problem with the file
   { 
     fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[fnum], errbuf); 
     return(2); 
   } 
   else
   {
     printf("Processing packets in %s\n", argv[fnum]);
   }
   
   // Begin processing the packets in this file

   while (packet = pcap_next(handle,&header)) 
   { 
    pkt_counter++;                  
    //printf("Processing packet number %d\n", pkt_counter);
    //printf("#");
    u_char *pkt_ptr = (u_char *)packet;      // Cast a pointer to the packet data

    //First check type of ethernet header

    ether_offset = ethernet_header(pkt_ptr);
    if (ether_offset == 0)
    {
	continue;
    }
    pkt_ptr += ether_offset;

    // Now move on to inner IP header
    ip_offset = inner_ip_header(pkt_ptr, pnt_ip_protocol, pnt_ip_length);
    if (ip_offset == 0)
    {
        continue;
    }    

    if(ip_length > 65535)
    {
      arr_iplength[65535]++;	// Maximum IP packet length should be 65535. This catches longer packets.
    }
    else
    {
      arr_iplength[(ip_length-1)]++;
    }
    
    if(ip_length > 1500)
    {
           fprintf(f_err, "Error, long IP packet. Packet Number: %lu. Packet Length: %d\n", pkt_counter, ip_length);
    }

    user_pkt_counter++;
    user_total_volume += ip_length;
    
    arr_protocol[ip_protocol][0] += ip_length;


    // Look at next header if UDP or TCP
    if(ip_protocol == 17)				// UDP
    {
     udp_counter++;
     pkt_ptr += ip_offset;
     port_number = udp_header(pkt_ptr, port);  //UDP header always 8 bytes
     udp_len = ip_length - ip_offset - 8;
     arr_udp_port[port_number] += ip_length;
     udp_total_volume += ip_length;
     arr_udp_len[udp_len]++;
    }
    
    if(ip_protocol == 6)                                // TCP
    {
     tcp_counter++;
     pkt_ptr += ip_offset;
     tcp_hdr_len = tcp_header(pkt_ptr, port, pnt_port_number, pnt_tcp_flags); 
     arr_tcp_port[port_number] += ip_length;
     tcp_total_volume += ip_length;
    
     tcp_length = ip_length - ip_offset - tcp_hdr_len; // Length of data in TCP packet
     arr_tcp_len[tcp_length]++;

     while (tcp_flags > 32)
	tcp_flags -= 32;		//Ignore all URG, ECE, CWR flags

     if ((tcp_flags == 2) || (tcp_flags == 10))   // SYN; SYN/PSH
	syn_counter++;
     else if ((tcp_flags == 18) || (tcp_flags == 26))   // SYN/ACK; SYN/ACK/PSH
        syn_ack_counter++;
     else if ((tcp_flags == 1) || (tcp_flags == 9))     // FIN; FIN/PSH
        fin_counter++;
     else if ((tcp_flags == 17) || (tcp_flags == 25))    // FIN/ACK; FIN/ACK/PSH
        fin_ack_counter++;
     else if (((tcp_flags == 16) || (tcp_flags == 24)) && (tcp_length == 0))   // ACK; ACK/PSH
        pure_ack_counter++;
     else if ((tcp_flags == 4) || (tcp_flags == 20) || (tcp_flags == 12) || (tcp_flags == 28))
        reset_counter++;      // RST; RST/ACK; RST/PSH; RST/ACK/PSH; 
     else if ((tcp_flags == 3) || (tcp_flags == 11) || (tcp_flags == 19) || (tcp_flags == 27))
        syn_fin_counter++;    // SYN/FIN; SYN/FIN/PSH; SYN/ACK/FIN; SYN/ACK/FIN/PSH
     else if ((tcp_flags == 6) || (tcp_flags == 14) || (tcp_flags == 22) || (tcp_flags == 30))
        syn_rst_counter++;    // SYN/RST; SYN/RST/PSH; SYN/ACK/RST; SYN/ACK/RST/PSH
     else if ((tcp_flags == 5) || (tcp_flags == 13))  // FIN/RST; FIN/RST/PSH
        fin_rst_counter++;
     else if (tcp_length != 0)
     {   
        data_counter++;
     }
     else
     {
        weird_counter++;
	fprintf(f_err, "Unidentified TCP packet.  Packet Number: %lu. TCP Flags: %d\n", pkt_counter, tcp_flags);
     }
    }  
   }
   system("rm -rf tempfile");
 }

// Analysis complete, now print to output files

 //IPLenAnalysis.csv
 fprintf (f_ip_len, "Packet Length (bytes), Number of Packets\n");
 for (i = 0; i<65536; i++)
 {
    if (arr_iplength[i] != 0)   // Only print out when some packets with this length
    {
     fprintf (f_ip_len, "%d,%lu\n", (i+1), arr_iplength[i]);
    }
 } 

 fprintf(f_ip_len, "\nTotal number of IP packets: %lu\n", user_pkt_counter);
 fprintf(f_ip_len, "Total IP volume (bytes): %lu \n", user_total_volume);
 fprintf(f_ip_len, "Average IP packet length (bytes): %lu \n", user_total_volume/user_pkt_counter);

 //ProtocolAnalysis.csv
 fprintf (f_protocol, "Protocol ID/Name, Number of Bytes\n");
 for (i = 0; i<256; i++)
 {
    if (arr_protocol[i][0] != 0)
    {
      fprintf (f_protocol, "%d,%lu\n", i, arr_protocol[i][0]);
    }
 }

 fprintf(f_protocol, "\nTotal volume (bytes) : %lu \n", user_total_volume);


 //TCPPortAnalysis.csv
 fprintf (f_tcp_port, "Port Number/Name, Number of Bytes\n");
 for (i = 0; i<65536; i++)
 {
    if (arr_tcp_port[i] != 0)
    {
      fprintf (f_tcp_port, "%d,%lu\n", i, arr_tcp_port[i]);
    }
 } 

 fprintf (f_tcp_port, "\nTotal TCP volume (bytes): %lu\n", tcp_total_volume);
 

 //UDPPortAnalysis.csv
 fprintf (f_udp_port, "Port Number/Name, Number of Bytes\n");
 for (i = 0; i<65536; i++)
 {
    if (arr_udp_port[i] != 0)
    {
      fprintf (f_udp_port, "%d,%lu\n", i, arr_udp_port[i]);
    }
 } 

 fprintf (f_udp_port, "\nTotal UDP volume (bytes): %lu\n", udp_total_volume);


 //UDPLenAnalysis.csv
 fprintf (f_udp_len, "Payload Length (bytes), Number of Packets\n");
 for (i = 0; i<65536; i++)
 {
    if (arr_udp_len[i] != 0)
    {
      fprintf (f_udp_len, "%d,%lu\n", i, arr_udp_len[i]);
    }
 } 
    fprintf(f_udp_len, "\nAverage UDP packet length (bytes): %lu\n", udp_total_volume/udp_counter);


 //TCPLenAnalysis.csv
 fprintf (f_tcp_len, "Payload Length (bytes), Number of Packets\n");
 for (i = 0; i<65536; i++)
 {
    if (arr_tcp_len[i] != 0)
    {
      fprintf (f_tcp_len, "%d,%lu\n", i, arr_tcp_len[i]);
    }
 } 
    fprintf(f_tcp_len, "\nTotal number of TCP packets: %lu\n", tcp_counter);
    fprintf(f_tcp_len, "Total number of SYN packets: %lu\n", syn_counter);
    fprintf(f_tcp_len, "Total number of SYN, ACK packets: %lu\n", syn_ack_counter); 
    fprintf(f_tcp_len, "Total number of FIN packets: %lu\n", fin_counter); 
    fprintf(f_tcp_len, "Total number of FIN, ACK packets: %lu\n", fin_ack_counter);
    fprintf(f_tcp_len, "Total number of pure ACK packets: %lu\n", pure_ack_counter);
    fprintf(f_tcp_len, "Total number of RST packets: %lu\n", reset_counter);
    fprintf(f_tcp_len, "Total number of SYN, FIN packets: %lu\n", syn_fin_counter);
    fprintf(f_tcp_len, "Total number of SYN, RST packets: %lu\n", syn_rst_counter);
    fprintf(f_tcp_len, "Total number of FIN, RST packets: %lu\n", fin_rst_counter);
    fprintf(f_tcp_len, "Total number of data packets: %lu\n", data_counter);
    fprintf(f_tcp_len, "Total number of weird packets: %lu\n", weird_counter);
    fprintf(f_tcp_len, "\nAverage TCP packet length (bytes): %lu\n", tcp_total_volume/tcp_counter);


 printf("\nSummary of Results:\n");
 printf("Number of user packets: %lu\n",user_pkt_counter);
 return 0;
}
