/* 
ethernet_header: function to analyse the ethernet header and return the header length.
Requires pointer to start of header 
Returns ethernet header length in bytes, returns 0 if error 
*/

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

int ethernet_header(u_char *pkt_ptr)
{
      int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13]; 
      int ether_offset = 0; 
 
      if (ether_type == ETHER_TYPE_IP)        //most common 
        ether_offset = 14;
      else if (ether_type == ETHER_TYPE_8021Q)  
         ether_offset = 18; 
      else 
      {
         //printf("Unknown ethernet type, %04X, skipping...\n", ether_type);
         ether_offset = 0;
      }
    return ether_offset;
}

/* 
udp_header.  Function analyses UDP packet and returns length of packet (header + payload) in bytes
Requires a pointer to start of packet, port - whether looking at source or destination.
Also needs pointer to variable in which to store UDP port number.
*/

int udp_header(u_char *pkt_ptr, int port)
{
    struct udphdr *udp_hdr = (struct udphdr *)pkt_ptr;                    // Pointer to a UDP header structure
    int port_number;

    if (port == 0)
     {
        port_number = ntohs(udp_hdr->source);
     }
    else if (port == 1)
     {
        port_number = ntohs(udp_hdr->dest);         // Find source and destination ports	
     }
    else
     {
        //printf("Error: neither source nor destination port found");
        return 0;				     // Should be impossible for this is happen.
     }   
    
    return port_number;                                   // length of UDP packet (header and data)
}

/* 
tcp_header.  Function analyses tcp packet and returns length of tcp header in bytes.
Requires a pointer to start of header.  port = 0 if looking at source port, 1 if destination port.
Also needs pointer to variable in which to store port number and value of flags. 
*/

int tcp_header(u_char *pkt_ptr, int port, int *port_number, int *tcp_flags)
{
     struct tcphdr *tcp_hdr = (struct tcphdr *)pkt_ptr;   // Point to a TCP header structure
     int length;	// TCP header length 

     if (port == 0)
     {
        *port_number = ntohs(tcp_hdr->source);
     }
     else if (port == 1)
     {
        *port_number = ntohs(tcp_hdr->dest);         // Find source and destination ports	
     }
     else
     {
        //printf("Error: neither source nor destination port found");
        return 0; 				     // Should be impossible for this is happen.
     }

     length = (tcp_hdr->doff)*4;                     //Length of TCP header
     *tcp_flags = (int)(pkt_ptr[13]);
     return length;
}

/*
inner_ip_header.  Function analyses inner ip packet and returns header length in bytes.
Requires pointer to start of packet.
Also requires pointers to variables in whcih to store next packet protocol and total length of ip packet.
*/

int inner_ip_header(u_char *pkt_ptr, int *ip_protocol, int *ip_length)
{
    struct ip *ip_hdr = (struct ip *)pkt_ptr;          // Point to an IP header structure
    int ip_offset;
    
    if((ip_hdr->ip_v)!=4)	// Check header is an IPv4 header (will also fail most non IP headers)
    {
        //printf("Unknown packet type, skipping...\n");
        return 0;
    }

    ip_offset = (ip_hdr->ip_hl)*4;                 // Header length in bytes
    
    if(ip_offset<19)				   // Check header is above minimum length
    {
        //printf("Unknown packet type, skipping...\n");
        return 0;
    }   

    *ip_protocol = ip_hdr->ip_p;                       // Read next protocol field
    *ip_length = ntohs(ip_hdr->ip_len);                // Read packet length
    return ip_offset;
}
