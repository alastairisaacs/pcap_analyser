# pcap_analyser

This script will take a pcap.gz file and produce statistics on the packets contained within.  Currently only supports standard IPv4 packets.

Requires installation of libpcap-dev library.  This can be done on ubuntu with the command "sudo apt-get install libpcap-dev"

Usage: ./traffic_analysis pcapfile1 [pcapfile2 ... pcapfileN]

Note: file must be in format pcap.gz

After running the following files are output:

IPLenAnalysis.csv	Contains a list of IP packet lengths (in bytes) found and their frequency.  Gives total volume of IP data and average IP packet length.


ProtocolAnalysis.csv	Contains a list of IP protocol numbers found and their frequency.   A list of IP protocol numbers can found here: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers


TCPPortAnalysis.csv	Contains a list of TCP port numbers found and the number of bytes of data sent to that port number.  A list of TCP port numbers can be found here: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers


UDPPortAnalysis.csv	Contains a list of UDP port numbers found and the number of bytes of data sent to that port number.  A list of UDP port numbers can be found here: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers


UDPLenAnalysis.csv	Contains a list of UDP payload length (in bytes) found and their frequency.  Also gives the average UDP payload length.


TCPLenAnalysis.csv	Contains a list of TCP payload length (in bytes) found and their frequency.  Gives average TCP payload length.   Also gives the total number of the following TCP type packets found:
	-SYN
	-SYN,ACK
	-FIN
	-FIN,ACK
	-ACK
	-RST
	-SYN,FIN
	-SYN,RST
	-FIN,RST
	-Data packets
	-Unidentified

ErrorLog.csv		Error output.
