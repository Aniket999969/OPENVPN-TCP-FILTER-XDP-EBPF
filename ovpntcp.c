#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>




SEC("xdp/openvpn-tcp")
int openvpntcp(xdp_md *ctx struct header_pointers *hdr) {
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct ethhdr *eth = data;
    
    if (data + sizeof (struct ethhdr) > data_end)
      return XDP_DROP;
   
   // we will make sure that the packet is TCP not udp so the fool who is trying to send udp on tcp will be dropped :)

   	if (ip_hdr->protocol != IPPROTO_TCP)
		 return XDP_PASS;
     
    // ip checksums we make sure that ip meets our requirements TTL really depends on your Netowrk make sure to change it depending how many hops your network takes to reach a certain location. 
    if (ip_hdr->version == 4)
     return XDP_PASS;
    
    if (ip_hdr->ttl  <= 64)
     return XDP_PASS;

    if (ip_hdr->ttl  > 29)
     return XDP_PASS;
    
    if (ip_hdr->ihl == 5)
     return XDP_PASS;
    
		// TCP doesn't normally use fragments, and XDP can't reassemble them.
		if ((ip_hdr->frag_off & bpf_htons(IP_DF | IP_MF | IP_OFFSET)) != bpf_htons(IP_DF))
		 return XDP_DROP;


  // TCP headers checksum.
    
  	if (tcp_hdr + 60 > data_end)
		return XDP_DROP;
    

}