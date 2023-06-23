#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_arp.h>
#include <rte_ip.h>

#include <base.h>

// 90:e2:ba:f7:32:69
struct rte_ether_addr my_mac = {
	.addr_bytes = {0x90, 0xe2, 0xba, 0xf7, 0x32, 0x69}
};
// 90:E2:BA:F7:30:1D
struct rte_ether_addr source_mac = {
	.addr_bytes = {0x90, 0xe2, 0xba, 0xf7, 0x30, 0x1d}
};
// 90:E2:BA:F7:31:CD
struct rte_ether_addr target_mac = {
	.addr_bytes = {0x90, 0xe2, 0xba, 0xf7, 0x31, 0xcd}
};
// // 90:e2:ba:f7:32:69
// unsigned char my_mac[] = {0x90, 0xe2, 0xba, 0xf7, 0x32, 0x69};
// // 90:E2:BA:F7:30:1D
// unsigned char source_mac[] = {0x90, 0xe2, 0xba, 0xf7, 0x30, 0x1d};
// // 90:E2:BA:F7:31:CD
// unsigned char target_mac[] = {0x90, 0xe2, 0xba, 0xf7, 0x31, 0xcd};
void standard_acl(struct rte_mbuf *pkt_buf, struct rte_lpm **lpm4, struct rte_lpm6 **lpm6) {
	void *payload = rte_pktmbuf_mtod(pkt_buf, void *);
	void *data_end = (void *)(long)payload + pkt_buf->pkt_len;
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)payload;
	/* Check if eth header is within bounds */
    if ((void *) (eth + 1) > data_end)
    {
		rte_pktmbuf_free(pkt_buf);
		return;
    }
	if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) 
		|| eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
	{
		uint32_t permitted_src;
		int32_t lookup;
		if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		{
			struct rte_ipv4_hdr *iph = payload + sizeof(struct rte_ether_hdr);
			/* Check if IP header is within bounds */
            if ((void *) (iph + 1) > data_end)
            {
            	rte_pktmbuf_free(pkt_buf);
				return;
            }
			uint32_t src_ip = rte_be_to_cpu_32(iph->src_addr);
			lookup = rte_lpm_lookup(*lpm4, src_ip, &permitted_src);
		}
		else {
			struct rte_ipv6_hdr *ipv6h = payload + sizeof(struct rte_ether_hdr);
			/* Check if IP header is within bounds */
            if ((void *) (ipv6h + 1) > data_end)
            {
            	rte_pktmbuf_free(pkt_buf);
				return;
            }
			uint8_t *src_ip = ipv6h->src_addr;
			lookup = rte_lpm6_lookup(*lpm6, src_ip, &permitted_src);
		}
		if(!lookup)
		{
			if(permitted_src){
				// if (!(memcmp(eth->src_addr.addr_bytes, source_mac, RTE_ETHER_ADDR_LEN) 
				// || memcmp(eth->dst_addr.addr_bytes, my_mac, RTE_ETHER_ADDR_LEN))) {
				// 	memcpy(eth->src_addr.addr_bytes, my_mac, RTE_ETHER_ADDR_LEN);
				// 	memcpy(eth->dst_addr.addr_bytes, target_mac, RTE_ETHER_ADDR_LEN);
				// 	dpdk_out(pkt_buf);
				// 	rte_pktmbuf_free(pkt_buf);
				// }
				if (rte_is_same_ether_addr(&eth->src_addr, &source_mac) 
					&& rte_is_same_ether_addr(&eth->dst_addr, &my_mac)) {
						rte_ether_addr_copy(&my_mac, &eth->src_addr);
						rte_ether_addr_copy(&target_mac, &eth->dst_addr);
						dpdk_out(pkt_buf);
						return;
					}
			}
		}
	}
	rte_pktmbuf_free(pkt_buf);
	return;
}

void redirect(struct rte_mbuf *pkt_buf) {
	void *payload = rte_pktmbuf_mtod(pkt_buf, void *);
	void *data_end = (void *)(long)payload + pkt_buf->pkt_len;
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)payload;
	// /* Check if eth header is within bounds */
    if ((void *) (eth + 1) > data_end)
    {
		rte_pktmbuf_free(pkt_buf);
		return;
    }
	if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) 
		|| eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
	{
		// if (!(memcmp(eth->src_addr.addr_bytes, source_mac, RTE_ETHER_ADDR_LEN) 
		// || memcmp(eth->dst_addr.addr_bytes, my_mac, RTE_ETHER_ADDR_LEN))) {
		// 	memcpy(eth->src_addr.addr_bytes, my_mac, RTE_ETHER_ADDR_LEN);
		// 	memcpy(eth->dst_addr.addr_bytes, target_mac, RTE_ETHER_ADDR_LEN);
		// 	dpdk_out(pkt_buf);
		// 	rte_pktmbuf_free(pkt_buf);
		// }
		if (rte_is_same_ether_addr(&eth->src_addr, &source_mac) 
			&& rte_is_same_ether_addr(&eth->dst_addr, &my_mac)) {
				rte_ether_addr_copy(&my_mac, &eth->src_addr);
				rte_ether_addr_copy(&target_mac, &eth->dst_addr);
				dpdk_out(pkt_buf);
				return;
			}
	}
	rte_pktmbuf_free(pkt_buf);
	return;
}