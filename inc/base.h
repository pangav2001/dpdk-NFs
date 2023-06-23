#pragma once

#include <rte_mbuf.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ip.h>

#define NUM_OF_LPM_TRIES 2

/* DPDK functionality */
void dpdk_init(int *argc, char ***argv);
void dpdk_terminate(void);
void dpdk_poll(void);
void dpdk_out(struct rte_mbuf *pkt);

RTE_DECLARE_PER_LCORE(int, queue_id);

/* net */
void standard_acl(struct rte_mbuf *pkt_buf, struct rte_lpm **lpm4, struct rte_lpm6 **lpm6);
void redirect(struct rte_mbuf *pkt_buf);