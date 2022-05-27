/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include "args.h"
#include "worker.h"
#include "header.h"
#include "microhttpd.h"
#include "rte_lcore.h"
#include "rte_ring.h"
#include <pthread.h>
#include <rte_acl.h>
#include <rte_service.h>
#include <rte_service_component.h>
#include <rte_mbuf.h>
#include <signal.h>



static uint16_t reg_record[NUM_REG];
static uint64_t reg_clientreqid[NUM_REG];
static uint64_t sequence = 0;

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3
#define MEMPOOL_CACHE_SIZE 256
#define CLONEPOOL_CACHE_SIZE 512


struct thArgsConst {
    struct rte_mbuf *m;
    struct rte_mempool *header_pool;
    struct rte_ipv4_hdr *orig_ipv4_hdr;
    uint64_t *src_mac;
    unsigned int *dst_port;
};
struct thArgs {
    //struct rte_mempool *bootstrap_pool;
    struct thArgsConst *argsConst;
    uint64_t dst_mac;
    uint32_t dst_ip;
    int coreID;
    
};



/* send individual packet into designated ring buffer */
static inline int send_one_packet(struct rte_mbuf *m, uint32_t res,
                                  struct rte_ring **rings)
{
    if (likely(res != 0))
    {
        rte_ring_enqueue(rings[res], m);
        return 1;
    }
    else
    {
        /* Not in the ACL list, drop it */
        rte_pktmbuf_free(m);
        return 0;
    }
}

/* Send packets into designated ring buffers
 * returns how many packets sent to rings.
 */
static inline int send_packets(struct rte_mbuf **m, uint32_t *res, int num,
                               struct rte_ring **rings)
{
    int i;
    int count = 0;
    /* Prefetch first packets */
    for (i = 0; i < PREFETCH_OFFSET && i < num; i++)
    {
        rte_prefetch0(rte_pktmbuf_mtod(m[i], void *));
    }
    for (i = 0; i < (num - PREFETCH_OFFSET); i++)
    {
        rte_prefetch0(rte_pktmbuf_mtod(m[i + PREFETCH_OFFSET], void *));
        count += send_one_packet(m[i], res[i], rings);
    }
    /* Process left packets */
    for (; i < num; i++)
    {
        count += send_one_packet(m[i], res[i], rings);
    }

    return count;
}

/*
 * Handles interrupt signals.
 */
static void sig_handler(int sig_num)
{
    LOG_INFO(USER1, "Exiting on signal '%d'\n", sig_num);

    // set quit flag for rx thread to exit
    quit_signal = 1;
}

/*
 * Prints packet processing metrics to stdout.
 */
static void
print_stats(rx_worker_params *rx_params, const unsigned nb_rx_workers,
            mrtom_worker_params *mrtom_param, const unsigned nb_tx_workers)
{
    struct rte_eth_stats eth_stats;
    unsigned i;
    uint64_t in, out, depth, drops, ring_space, in_prev;
    const char clr[] = {27, '[', '2', 'J', '\0'};
    const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
    // app_stats stats;

    /* Clear screen and move to top left */
    printf("%s%s", clr, topLeft);

    // header
    printf("\033[1;33m");
    printf("\n %45s ESnet Fastcapa-ng\n", "");
    printf("\033[0m");
    printf("\n                   %15s %15s %15s %15s %15s %15s \n",
           " ----- in -----", "--- in MPPS ---", " --- queued ---",
           "----- out -----", "---- drops  ----", "-- ring space -");

    // summarize stats from each port
    in = out = depth = drops = 0;
    for (i = 0; i < rte_eth_dev_count_total(); i++)
    {
        rte_eth_stats_get(i, &eth_stats);
        in += eth_stats.ipackets;
        drops += eth_stats.ierrors + eth_stats.oerrors + eth_stats.rx_nombuf;
        printf("[nic-port-%d]       %15" PRIu64 " %15" PRIu64
               " %15s %15s %15" PRIu64 "\n",
               (unsigned int)i, eth_stats.ipackets, depth, "-", "-",
               eth_stats.ierrors + eth_stats.oerrors + eth_stats.rx_nombuf);

        
    }
    printf("\033[1;34m");
    printf("[nic]              %15" PRIu64 " %15" PRIu64 " %15s %15s %15" PRIu64
           "\n",
           in, depth, "-", "-", drops);
    printf("\033[0m");

    // summarize receive; from network to receive queues to flow rings
    in = out = depth = drops = ring_space = in_prev = 0;
    for (i = 0; i < nb_rx_workers; i++)
    {
        in += rx_params[i].stats.in;
        out += rx_params[i].stats.out;
        depth += rx_params[i].stats.depth;
        drops += rx_params[i].stats.drops;
        ring_space = rx_params[i].stats.ring_space;
        in_prev += rx_params[i].stats.in_prev;
        printf("[rx-worker-%02d]     %15" PRIu64 " %15f %15s %15" PRIu64
               " %15" PRIu64 " %15" PRIu64 "\n",
               i, rx_params[i].stats.in,
               ((float)(rx_params[i].stats.in) - rx_params[i].stats.in_prev) /
                   1000000,
               "-", rx_params[i].stats.out, rx_params[i].stats.drops,
               ring_space);
        rx_params[i].stats.in_prev = rx_params[i].stats.in;

        

    }
    printf("\033[1;34m");
    printf("[rx]               %15" PRIu64 " %15f %15s %15" PRIu64 " %15" PRIu64
           "\n",
           in, ((float)(in)-in_prev) / 1000000, "-", out, drops);
    printf("\033[0m");


    // summarize mrtom receive; from network to receive queues to flow rings
    in = out = depth = drops = ring_space = in_prev = 0;
    for (i = 0; i < nb_tx_workers; i++)
    {
        in += mrtom_param->stats.in;
        out += mrtom_param->stats.out;
        depth += mrtom_param->stats.depth;
        drops += mrtom_param->stats.drops;
        ring_space = mrtom_param->stats.ring_space;
        in_prev += mrtom_param->stats.in_prev;
        printf("[mt-worker-%02d]     %15" PRIu64 " %15f %15s %15" PRIu64
                " %15" PRIu64 " %15" PRIu64 "\n",
                i, mrtom_param->stats.in,
                ((float)(mrtom_param->stats.in) - mrtom_param->stats.in_prev) /
                    1000000,
                "-", mrtom_param->stats.out, mrtom_param->stats.drops,
                ring_space);
        mrtom_param->stats.in_prev = mrtom_param->stats.in;

    }

    
    printf("\033[1;34m");
    printf("[mrtom]               %15" PRIu64 " %15f %15s %15" PRIu64 " %15" PRIu64
           "\n",
           in, ((float)(in)-in_prev) / 1000000, "-", out, drops);
    printf("\033[0m");
    
    printf("\n");
    //printf("mrtom ring size is %d\n", rte_ring_free_count(mrtom_param->input_ring));
    fflush(stdout);
}


static void
swap_mac(struct rte_ether_hdr *eth_hdr)
{
		struct rte_ether_addr ether_tmp;
		rte_ether_addr_copy(&eth_hdr->s_addr, &ether_tmp);
		rte_ether_addr_copy(&eth_hdr->d_addr, &eth_hdr->s_addr);
		rte_ether_addr_copy(&ether_tmp, &eth_hdr->d_addr);
}

static void
update_arp_src_mac(struct rte_ether_addr *src_addr, uint64_t addr)
{
	src_addr->addr_bytes[0] = (uint8_t) (addr >> 40);
	src_addr->addr_bytes[1] = (uint8_t) (addr >> 32);
	src_addr->addr_bytes[2] = (uint8_t) (addr >> 24);
	src_addr->addr_bytes[3] = (uint8_t) (addr >> 16);
	src_addr->addr_bytes[4] = (uint8_t) (addr >> 8);
	src_addr->addr_bytes[5] = (uint8_t) (addr >> 0);
}

static void
update_mac(struct rte_ether_addr *dst_addr, uint64_t addr)
{
	dst_addr->addr_bytes[0] = (uint8_t) (addr >> 40);
	dst_addr->addr_bytes[1] = (uint8_t) (addr >> 32);
	dst_addr->addr_bytes[2] = (uint8_t) (addr >> 24);
	dst_addr->addr_bytes[3] = (uint8_t) (addr >> 16);
	dst_addr->addr_bytes[4] = (uint8_t) (addr >> 8);
	dst_addr->addr_bytes[5] = (uint8_t) (addr >> 0);
}

static uint64_t
eth_hdr_to_uint64t(struct rte_ether_addr *eth_addr)
{
	uint64_t ret = 0;
	ret = (ret << 8) + eth_addr->addr_bytes[0];
	ret = (ret << 8) + eth_addr->addr_bytes[1];
	ret = (ret << 8) + eth_addr->addr_bytes[2];
	ret = (ret << 8) + eth_addr->addr_bytes[3];
	ret = (ret << 8) + eth_addr->addr_bytes[4];
	ret = (ret << 8) + eth_addr->addr_bytes[5];
	
	return ret;
}

static void
update_new_ipv4_header(struct rte_ipv4_hdr *new_ipv4_hdr,
                       struct rte_ipv4_hdr *old_ipv4_hdr,
                       uint32_t dst_ip)
{
    new_ipv4_hdr->version_ihl = old_ipv4_hdr->version_ihl;
    new_ipv4_hdr->type_of_service = old_ipv4_hdr->type_of_service;
    new_ipv4_hdr->total_length = old_ipv4_hdr->total_length;
    new_ipv4_hdr->packet_id = old_ipv4_hdr->packet_id;
    new_ipv4_hdr->fragment_offset = old_ipv4_hdr->fragment_offset;
    new_ipv4_hdr->time_to_live = old_ipv4_hdr->time_to_live;
    new_ipv4_hdr->next_proto_id = old_ipv4_hdr->next_proto_id;
    new_ipv4_hdr->hdr_checksum = 0;
    new_ipv4_hdr->src_addr = old_ipv4_hdr->src_addr;
    new_ipv4_hdr->dst_addr = rte_bswap32(dst_ip);
    
    new_ipv4_hdr->hdr_checksum = rte_ipv4_cksum(new_ipv4_hdr);
}

static void
mrtom_forward(struct rte_mbuf *m, struct rte_ether_hdr *eth_hdr)
{
    assert(eth_hdr != NULL);
	//	dst_port = l2fwd_dst_ports[portid];
	unsigned dst_port = 0;
	//struct rte_eth_dev_tx_buffer *buffer;
	//int sent;
	
	// switch (eth_hdr_to_uint64t(&eth_hdr->d_addr)) {
	// 	case SM111MAC :
	// 		dst_port = SM111PORT;
	// 		break;

	// 	case SM112MAC :
	// 		dst_port = SM112PORT;
	// 		break;

	// 	case SM113MAC :
	// 		dst_port = SM113PORT;
	// 		break;

	// 	case SM114MAC :
	// 		dst_port = SM114PORT;
	// 		break;

	// 	case SM115MAC :
	// 		dst_port = SM115PORT;
	// 		break;

	// 	case SM116MAC :
	// 		dst_port = SM116PORT;
	// 		break;
			
	// 	case SM117MAC :
	// 		dst_port = SM117PORT;
	// 		break;
			
	// 	case SM118MAC :
	// 		dst_port = SM118PORT;
	// 		break;
			
			
	// 	default :
	// 		rte_pktmbuf_free(m);
	// 		return;
			
	// }

	//buffer = tx_buffer[dst_port];
	//sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
	rte_eth_tx_burst(dst_port, 0, &m, 1);
}


static bool
construct_arp_reply(struct rte_ether_hdr *eth_hdr, struct rte_arp_hdr *arp_hdr)
{
	arp_hdr->arp_opcode = rte_bswap16(RTE_ARP_OP_REPLY);
	
	//printf("arp src ip is : %x\n", arp_ipv4->arp_sip);
	//printf("arp dst ip is : %x\n", arp_ipv4->arp_tip);
	
	uint32_t tmp_ip = arp_hdr->arp_data.arp_tip;
	arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
	arp_hdr->arp_data.arp_sip = tmp_ip;
	
	arp_hdr->arp_data.arp_tha = arp_hdr->arp_data.arp_sha;
	
	//printf("arp dst ip is : %x\n", tmp_ip);
	
	switch (rte_bswap32(tmp_ip)) {
		case SM111IP :
			update_arp_src_mac(&arp_hdr->arp_data.arp_sha, SM111MAC);
			break;

		case SM112IP :
			update_arp_src_mac(&arp_hdr->arp_data.arp_sha, SM112MAC);
			break;

		case SM113IP :
			update_arp_src_mac(&arp_hdr->arp_data.arp_sha, SM113MAC);
			break;

		case SM114IP :
			update_arp_src_mac(&arp_hdr->arp_data.arp_sha, SM114MAC);
			break;

		case SM115IP :
			update_arp_src_mac(&arp_hdr->arp_data.arp_sha, SM115MAC);
			break;

		case SM116IP :
			update_arp_src_mac(&arp_hdr->arp_data.arp_sha, SM116MAC);
			break;
			
		case SM117IP :
			update_arp_src_mac(&arp_hdr->arp_data.arp_sha, SM117MAC);
			break;
			
		case SM118IP :
			update_arp_src_mac(&arp_hdr->arp_data.arp_sha, SM118MAC);
			break;
			
			
		default :
			return false;
			
	}
	swap_mac(eth_hdr);
	//RTE_LOG(INFO, L2FWD, "last 2 byte of dst ether is %x \n", arp_hdr->arp_data.arp_tha.addr_bytes[5]);
	return true;			
}



void *th_func(void * vargp)
{  
    struct thArgs *arg = (struct thArgs *) vargp;
    //we can set one or more bits here, each one representing a single CPU
    cpu_set_t cpuset; 

    int cpuID = arg->coreID;
    
    //CPU_ZERO(&cpuset);       //clears the cpuset
    //CPU_SET(cpuID , &cpuset); //set CPU 2 on cpuset


    /*
     * cpu affinity for the calling thread 
     * first parameter is the pid, 0 = calling thread
     * second parameter is the size of your cpuset
     * third param is the cpuset in which your thread will be
     * placed. Each bit represents a CPU
     */
    //sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    struct rte_mbuf *hdr;
    struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *n_ipv4_hdr;
    uint64_t dst_mac = arg->dst_mac;
    uint64_t dst_ip = arg->dst_ip;

    assert((hdr = rte_pktmbuf_alloc(arg->argsConst->header_pool)) != NULL);
	hdr->next = arg->argsConst->m;
    hdr->pkt_len = (uint16_t)(hdr->data_len + arg->argsConst->m->pkt_len);
    hdr->nb_segs = arg->argsConst->m->nb_segs + 1;

    n_ipv4_hdr = (struct rte_ipv4_hdr *)
        rte_pktmbuf_prepend(hdr, (uint16_t)sizeof(*n_ipv4_hdr));
    update_new_ipv4_header(n_ipv4_hdr, arg->argsConst->orig_ipv4_hdr, dst_ip);
    eth_hdr = (struct rte_ether_hdr *)
		rte_pktmbuf_prepend(hdr, (uint16_t)sizeof(*eth_hdr));
    update_mac(&eth_hdr->s_addr, *arg->argsConst->src_mac);
    update_mac(&eth_hdr->d_addr, dst_mac);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);    
    
    
    rte_eth_tx_burst(*arg->argsConst->dst_port, 0, &hdr, 1);
    pthread_exit(NULL);
}

static void
mrtom_process_request(struct rte_mbuf *m,
	               struct rte_ipv4_hdr *ip_hdr,
				   struct rte_udp_hdr *udp_hdr,
				   struct rte_paxos_hdr *paxos_hdr,
                   struct rte_mempool *header_pool,
                   struct rte_mempool *clone_pool,
                   struct rte_ring **output_rings)
{
	// printf("  process request message\n");
	struct rte_paxos_request_hdr *request_hdr = (struct rte_paxos_request_hdr *)(paxos_hdr + 1);
	uint16_t index = 0;	
	unsigned dst_port = 0;
    // assert(output_rings);
	//struct rte_eth_dev_tx_buffer *buffer;
	//int sent;
	index += (rte_bswap32(ip_hdr->src_addr) & 0xff) << 8;
	index += (rte_bswap16(udp_hdr->src_port) & 0xff);


	//update register
	reg_record[index] = MRTOM_REQ_BITMASK;
	reg_clientreqid[index] = paxos_hdr->clientreqid;
	//printf("    current request index is %d\n", index);
	
	//printf("    current request id is %lx\n", reg_clientreqid[index]);
	
	//modify packet
	udp_hdr->dgram_cksum = 0;
	request_hdr->orig_udp_src = udp_hdr->src_port;
	udp_hdr->src_port = 0;
	request_hdr->session_id = rte_bswap64(SESSION_ID);
	request_hdr->nr_groups = rte_bswap32(NR_GROUPS);// currently nr_groups == 1
	request_hdr->gr_id = 0;
	request_hdr->gr_sequence = rte_bswap64(sequence);
	sequence ++;

	//multicast to 3 ports
    assert(clone_pool != NULL);
    assert(header_pool != NULL);
    //save src mac
    struct rte_ether_hdr *orig_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint64_t src_mac = eth_hdr_to_uint64t(&orig_eth_hdr->s_addr);
    // remove original ether header
    struct rte_ipv4_hdr orig_ipv4_hdr = 
        (struct rte_ipv4_hdr){.version_ihl = ip_hdr->version_ihl,
                              .type_of_service = ip_hdr->type_of_service,
                              .total_length = ip_hdr->total_length,
                              .packet_id = ip_hdr->packet_id,
                              .fragment_offset = ip_hdr->fragment_offset,
                              .time_to_live = ip_hdr->time_to_live,
                              .next_proto_id = ip_hdr->next_proto_id,
                              .hdr_checksum = 0,
                              .src_addr = ip_hdr->src_addr,
                              .dst_addr = ip_hdr->dst_addr};
    
    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
    // remove original ipv4 hdr
    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ipv4_hdr));
    struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *n_ipv4_hdr;
	

    uint8_t exp_size = 7;
    struct rte_mbuf *hdr[exp_size]; 
    
    //update refcnt
    rte_pktmbuf_refcnt_update(m, exp_size);



    /////////////////////////////////////////
    // int factor = 1;
    // struct thArgsConst argsConst = 
    //     (struct thArgsConst){.m = m,
    //                           .header_pool = header_pool,
    //                           .orig_ipv4_hdr = &orig_ipv4_hdr,
    //                           .src_mac = &src_mac,
    //                           .dst_port = &dst_port};
 
    // pthread_t thr[factor];
    // int i, rc;
    // /* create a thread_data_t argument array */
    // struct thArgs args[factor];
    // args[0].coreID = 1;
    // args[0].dst_ip = SM112IP;
    // args[0].dst_mac = SM111MAC;
    // args[0].argsConst = &argsConst;

    // /* create threads */
    // for (i = 0; i < factor; i++) {
    //     if ((rc = pthread_create(&thr[i], NULL, th_func, &args[i]))) {
    //         LOG_INFO(USER1, "error: pthread_create, rc: %d\n", rc);
    //         exit(1);
    //     }
    // }
    // /* block until all threads complete */
    // for (i = 0; i < factor; ++i) {
    //     pthread_join(thr[i], NULL);
    // }
    //////////////////////////////////////////
    // send SM111
	assert((hdr[0] = rte_pktmbuf_alloc(header_pool)) != NULL);
	hdr[0]->next = m;
    hdr[0]->pkt_len = (uint16_t)(hdr[0]->data_len + m->pkt_len);
    hdr[0]->nb_segs = m->nb_segs + 1;

    n_ipv4_hdr = (struct rte_ipv4_hdr *)
        rte_pktmbuf_prepend(hdr[0], (uint16_t)sizeof(*n_ipv4_hdr));
    update_new_ipv4_header(n_ipv4_hdr, &orig_ipv4_hdr, SM111IP);
    eth_hdr = (struct rte_ether_hdr *)
		rte_pktmbuf_prepend(hdr[0], (uint16_t)sizeof(*eth_hdr));
    update_mac(&eth_hdr->s_addr, src_mac);
    update_mac(&eth_hdr->d_addr, SM111MAC);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);    
    
    //rte_ring_enqueue(output_rings[1], hdr);
    //rte_ring_enqueue_burst(output_rings[1], (void*) hdr, 1, NULL);
    //rte_eth_tx_burst(dst_port, 0, &hdr, 1);
	//rte_pktmbuf_free(hdr);

    // send SM112
	assert((hdr[1] = rte_pktmbuf_alloc(header_pool)) != NULL);
	hdr[1]->next = m;
    hdr[1]->pkt_len = (uint16_t)(hdr[1]->data_len + m->pkt_len);
    hdr[1]->nb_segs = m->nb_segs + 1;

    n_ipv4_hdr = (struct rte_ipv4_hdr *)
        rte_pktmbuf_prepend(hdr[1], (uint16_t)sizeof(*n_ipv4_hdr));
    update_new_ipv4_header(n_ipv4_hdr, &orig_ipv4_hdr, SM112IP);
    eth_hdr = (struct rte_ether_hdr *)
		rte_pktmbuf_prepend(hdr[1], (uint16_t)sizeof(*eth_hdr));
    update_mac(&eth_hdr->s_addr, src_mac);
    update_mac(&eth_hdr->d_addr, SM112MAC);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);    
    
    
    
    // send SM116
	assert((hdr[2] = rte_pktmbuf_alloc(header_pool)) != NULL);
	hdr[2]->next = m;
    hdr[2]->pkt_len = (uint16_t)(hdr[2]->data_len + m->pkt_len);
    hdr[2]->nb_segs = m->nb_segs + 1;

    n_ipv4_hdr = (struct rte_ipv4_hdr *)
        rte_pktmbuf_prepend(hdr[2], (uint16_t)sizeof(*n_ipv4_hdr));
    update_new_ipv4_header(n_ipv4_hdr, &orig_ipv4_hdr, SM116IP);
    eth_hdr = (struct rte_ether_hdr *)
		rte_pktmbuf_prepend(hdr[2], (uint16_t)sizeof(*eth_hdr));
    update_mac(&eth_hdr->s_addr, src_mac);
    update_mac(&eth_hdr->d_addr, SM116MAC);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);    
    
    
    
    // send SM117
	assert((hdr[3] = rte_pktmbuf_alloc(header_pool)) != NULL);
	hdr[3]->next = m;
    hdr[3]->pkt_len = (uint16_t)(hdr[3]->data_len + m->pkt_len);
    hdr[3]->nb_segs = m->nb_segs + 1;

    n_ipv4_hdr = (struct rte_ipv4_hdr *)
        rte_pktmbuf_prepend(hdr[3], (uint16_t)sizeof(*n_ipv4_hdr));
    update_new_ipv4_header(n_ipv4_hdr, &orig_ipv4_hdr, SM117IP);
    eth_hdr = (struct rte_ether_hdr *)
		rte_pktmbuf_prepend(hdr[3], (uint16_t)sizeof(*eth_hdr));
    update_mac(&eth_hdr->s_addr, src_mac);
    update_mac(&eth_hdr->d_addr, SM117MAC);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);    
    
    
	// send SM118
	assert((hdr[4] = rte_pktmbuf_alloc(header_pool)) != NULL);
	hdr[4]->next = m;
    hdr[4]->pkt_len = (uint16_t)(hdr[4]->data_len + m->pkt_len);
    hdr[4]->nb_segs = m->nb_segs + 1;

    n_ipv4_hdr = (struct rte_ipv4_hdr *)
        rte_pktmbuf_prepend(hdr[4], (uint16_t)sizeof(*n_ipv4_hdr));
    update_new_ipv4_header(n_ipv4_hdr, &orig_ipv4_hdr, SM118IP);
    eth_hdr = (struct rte_ether_hdr *)
		rte_pktmbuf_prepend(hdr[4], (uint16_t)sizeof(*eth_hdr));
    update_mac(&eth_hdr->s_addr, src_mac);
    update_mac(&eth_hdr->d_addr, SM118MAC);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);    
    
    
    // send SM114
	assert((hdr[5] = rte_pktmbuf_alloc(header_pool)) != NULL);
	hdr[5]->next = m;
    hdr[5]->pkt_len = (uint16_t)(hdr[5]->data_len + m->pkt_len);
    hdr[5]->nb_segs = m->nb_segs + 1;

    n_ipv4_hdr = (struct rte_ipv4_hdr *)
        rte_pktmbuf_prepend(hdr[5], (uint16_t)sizeof(*n_ipv4_hdr));
    update_new_ipv4_header(n_ipv4_hdr, &orig_ipv4_hdr, SM118IP);
    eth_hdr = (struct rte_ether_hdr *)
		rte_pktmbuf_prepend(hdr[5], (uint16_t)sizeof(*eth_hdr));
    update_mac(&eth_hdr->s_addr, src_mac);
    update_mac(&eth_hdr->d_addr, SM114MAC);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);    
    
    
    // send SM113
	assert((hdr[6] = rte_pktmbuf_alloc(header_pool)) != NULL);
	hdr[6]->next = m;
    hdr[6]->pkt_len = (uint16_t)(hdr[6]->data_len + m->pkt_len);
    hdr[6]->nb_segs = m->nb_segs + 1;

    n_ipv4_hdr = (struct rte_ipv4_hdr *)
        rte_pktmbuf_prepend(hdr[6], (uint16_t)sizeof(*n_ipv4_hdr));
    update_new_ipv4_header(n_ipv4_hdr, &orig_ipv4_hdr, SM118IP);
    eth_hdr = (struct rte_ether_hdr *)
		rte_pktmbuf_prepend(hdr[6], (uint16_t)sizeof(*eth_hdr));
    update_mac(&eth_hdr->s_addr, src_mac);
    update_mac(&eth_hdr->d_addr, SM113MAC);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);    
    
    
  

    
    
    //////////////////////////////////////////////

	// TODO: store the packet for retransmission
	//rte_pktmbuf_free(m);

    // struct rte_mbuf *hdr;
    // struct rte_mbuf *buf;
    // buf = rte_pktmbuf_clone(m, clone_pool);
    // hdr = rte_pktmbuf_alloc(header_pool);
    // hdr->next = buf;
    // hdr->pkt_len = (uint16_t)(hdr->data_len + buf->pkt_len);
    // hdr->nb_segs = (uint8_t)(buf->nb_segs + 1);
    // rte_ring_enqueue(output_rings[0], hdr);
    // buf = rte_pktmbuf_clone(m, clone_pool);
    // hdr = rte_pktmbuf_alloc(header_pool);
    // hdr->next = buf;
    // hdr->pkt_len = (uint16_t)(hdr->data_len + buf->pkt_len);
    // hdr->nb_segs = (uint8_t)(buf->nb_segs + 1);
    // rte_ring_enqueue(output_rings[1], hdr);
    // rte_pktmbuf_free(m);
    



    rte_eth_tx_burst(dst_port, 0, hdr, exp_size);
    rte_pktmbuf_free(m);
    ///////////////////////////
    
    // struct rte_mbuf *cpy1 = rte_pktmbuf_copy(m, clone_pool, 0, UINT32_MAX);
    // struct rte_mbuf *cpy2 = rte_pktmbuf_copy(m, clone_pool, 0, UINT32_MAX);
    // rte_ring_enqueue(output_rings[0], cpy1);
    // rte_ring_enqueue(output_rings[1], cpy2);
    // rte_pktmbuf_free(m);
    
    ///////////////////////////////////////
}

static void
mrtom_process_reply(struct rte_mbuf *m,
	               struct rte_ether_hdr *eth_hdr,
				   struct rte_ipv4_hdr *ip_hdr,
				   struct rte_udp_hdr *udp_hdr,
				   struct rte_paxos_hdr *paxos_hdr)
{
    //printf("response received,\n");

	uint16_t index = 0;	
	index += (rte_bswap32(ip_hdr->dst_addr) & 0xff) << 8;
	index += (rte_bswap16(udp_hdr->dst_port) & 0xff);
	//printf("  processing reply begin\n");
	
	if(reg_clientreqid[index] != paxos_hdr->clientreqid) {
		rte_pktmbuf_free(m);
		return;
	}
	//printf("    processing reply\n");
    //printf("    received IP is %u\n", rte_bswap32(ip_hdr->src_addr));
    //printf("       SM116IP is %u\n", SM116IP);
    //printf("       SM117IP is %u\n", SM117IP);
    //printf("       SM118IP is %u\n", SM118IP);
    
	switch(rte_bswap32(ip_hdr->src_addr)) {
		case SM117IP :
			reg_record[index] = reg_record[index] & SM117MASK;
			break;
		case SM116IP :
			reg_record[index] = reg_record[index] & SM116MASK;
			break;
		case SM118IP :
			reg_record[index] = reg_record[index] & SM118MASK;
			break;
		default:
			rte_pktmbuf_free(m);
			return;
	}
	
	if(paxos_hdr->is_leader == rte_bswap16(1)) {
		reg_record[index] = reg_record[index] & LEADER_REPLY_MASK;	
	}
	//printf("    current reg_record is %d\n", reg_record[index]);

	if (reg_record[index] == 0b10100 ||
		reg_record[index] == 0b10010 ||
		reg_record[index] == 0b10001) {
		//printf("    forward decision\n");
		mrtom_forward(m, eth_hdr);
        //printf("response sent,\n");
	}
	else {
		rte_pktmbuf_free(m);
		return;
	}
	


}

static void
mrtom_process_recir(struct rte_mbuf *m,
	               struct rte_ipv4_hdr *ip_hdr,
				   struct rte_udp_hdr *udp_hdr)
{
	uint16_t index = 0;	
	index += (rte_bswap32(ip_hdr->src_addr) & 0xff) << 8;
	index += (rte_bswap16(udp_hdr->src_port) & 0xff);
	assert(m != NULL);
	assert(udp_hdr != NULL);

}

static void
mrtom_process_recir_last(struct rte_mbuf *m,
	               struct rte_ipv4_hdr *ip_hdr,
				   struct rte_udp_hdr *udp_hdr)
{
	uint16_t index = 0;	
	index += (rte_bswap32(ip_hdr->src_addr) & 0xff) << 8;
	index += (rte_bswap16(udp_hdr->src_port) & 0xff);
	assert(m != NULL);
	assert(udp_hdr != NULL);

}



static void
mrtom_process_core(struct rte_mbuf *m,
	               struct rte_ether_hdr *eth_hdr,
				   struct rte_ipv4_hdr *ip_hdr,
				   struct rte_udp_hdr *udp_hdr,
                   struct rte_mempool *header_pool,
                   struct rte_mempool *clone_pool,
                   struct rte_ring **output_rings)
{
	assert(ip_hdr != NULL);
	assert(m !=  NULL);
	//printf("process MRTOM message\n");

	struct rte_paxos_hdr *paxos_hdr = (struct rte_paxos_hdr *)(udp_hdr + 1);
	
	if (paxos_hdr->msg_type == rte_bswap16(MRTOM_MSG_REGULAR)) {
		mrtom_forward(m, eth_hdr);
		
	}
	else if (paxos_hdr->msg_type == rte_bswap16(MRTOM_MSG_REQUEST)) {
		mrtom_process_request(m, ip_hdr, udp_hdr, paxos_hdr, header_pool, clone_pool, output_rings);
	}
	else if (paxos_hdr->msg_type == rte_bswap16(MRTOM_MSG_REPLY)) {
		mrtom_process_reply(m, eth_hdr, ip_hdr, udp_hdr, paxos_hdr);
	}
	else if (paxos_hdr->msg_type == rte_bswap16(MRTOM_MSG_FAST_REPLY)) {
		mrtom_process_reply(m, eth_hdr, ip_hdr, udp_hdr, paxos_hdr);
	}
	else if (paxos_hdr->msg_type == rte_bswap16(MRTOM_MSG_RECIR)) {
		mrtom_process_recir(m, ip_hdr, udp_hdr);
	}
	else if (paxos_hdr->msg_type == rte_bswap16(MRTOM_MSG_RECIR_LAST)) {
		mrtom_process_recir_last(m, ip_hdr, udp_hdr);
	} 
		

}


static void
mrtom_process(struct rte_mbuf *m,
              struct rte_mempool *header_pool,
              struct rte_mempool *clone_pool,
              struct rte_ring **output_rings)
{
	//printf("start mrtom process\n");
	struct rte_ether_hdr *eth_hdr;

	


	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (eth_hdr->ether_type == rte_bswap16(RTE_ETHER_TYPE_ARP)) {
		//process and return arp reply
		struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
		printf("received arp packet\n");
		if (arp_hdr->arp_opcode == rte_bswap16(RTE_ARP_OP_REQUEST)) {
			//printf("received arp request packet\n");
			if(construct_arp_reply(eth_hdr, arp_hdr)) {
				mrtom_forward(m, eth_hdr);
				return;
			}
		}
	}
	else if (eth_hdr->ether_type == rte_bswap16(RTE_ETHER_TYPE_IPV4)) {
    	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    	
		if(ip_hdr->next_proto_id == IPPROTO_UDP) {
			//printf("received UDP packet\n");
		
			struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
			if (udp_hdr->dst_port == rte_bswap16(MRTOM_PORT) || 
			    udp_hdr->src_port == rte_bswap16(MRTOM_PORT)) {

				mrtom_process_core(m, eth_hdr, ip_hdr, udp_hdr, header_pool, clone_pool, output_rings);
				return;
			}

//				if (mrtom_process_core(ip_hdr, udp_hdr)) {
//					mrtom_forward(m, eth_hdr);
//					return;
//				}	
			
    	}
		
		
	}
	else {
		rte_pktmbuf_free(m);
		return;	
	}
	
	mrtom_forward(m, eth_hdr);
	return;

}

/*
 * Seperate mrtom worker to push multicast packets out.
 */
static int mrtom_worker(mrtom_worker_params *params)
{
    unsigned nb_in;
    const unsigned int rx_burst_size = params->rx_burst_size;

    struct rte_ring *input_ring = params->input_ring;
    // struct rte_mbuf *m;

    //struct rte_mbuf *pkts[rx_burst_size] = { NULL };
    struct rte_mbuf *pkts[MAX_RX_BURST_SIZE] = { NULL };
    

    LOG_INFO(USER1, "MRTOM worker started; core=%u, socket=%u \n", rte_lcore_id(),
             rte_socket_id());

    // struct rte_mempool *header_pool;
    // struct rte_mempool *clone_pool;
    unsigned int dst_port = params->tx_port;
    // int i;
    // const int attempts = 0;

    while (!quit_signal)
    {
        // dequeue packets from the ring
        nb_in = rte_ring_dequeue_burst(input_ring, (void *)pkts, rx_burst_size,
                                      NULL);

        // i = 0;
        // uint16_t nb_in = 0, nb_in_last = 0;//, nb_out = 0;
        // do
        // {
        //     nb_in_last =
        //         rte_ring_dequeue_burst(input_ring, &pkts[nb_in], rx_burst_size, NULL);
        //     nb_in += nb_in_last;

        // } while (++i < attempts && nb_in_last == rx_burst_size);
        params->stats.in += nb_in;



        
        // add each packet to the ring buffer
        if (likely(nb_in) > 0)
        {
            
            for (unsigned int i = 0; i < nb_in; i ++)
            {
                // // send SM111
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                
                //update_new_ipv4_header(n_ipv4_hdr, &orig_ipv4_hdr, SM111IP);
                if(params->worker_id == 0)
                    ip_hdr->dst_addr = rte_bswap32(SM111IP);
                else
                    ip_hdr->dst_addr = rte_bswap32(SM112IP);
                
    
                ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
                //update_mac(&eth_hdr->s_addr, src_mac);
                if(params->worker_id == 0)
                    update_mac(&eth_hdr->d_addr, SM111MAC);
                else
                    update_mac(&eth_hdr->d_addr, SM112MAC);

                eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);    
                
                // rte_ring_enqueue(output_rings[1], hdr);
                // //rte_ring_enqueue_burst(output_rings[1], (void*) hdr, 1, NULL);
                //sleep(1);
                //rte_eth_tx_burst(dst_port, 0, &pkts[i], 1);
                // //rte_pktmbuf_free(hdr);
            }
            
            rte_eth_tx_burst(dst_port, params->worker_id + 1, (void *)pkts, nb_in);
            
                            
            params->stats.out += nb_in;
            //params->stats.ring_space = rte_ring_free_count(input_ring);
            //params->stats.drops += (nb_in - nb_out);
        }
    }
    return 0;
}



/*
 * Process packets from a NIC queue.
 */
static int receive_worker(rx_worker_params *params)
{
    const uint8_t nb_ports = params->nb_ports;
    const unsigned socket_id = rte_socket_id();
    const uint16_t rx_burst_size = params->rx_burst_size;
    const uint16_t queue_id = params->queue_id;
    //struct rte_ring *output_ring = params->output_ring;
    int i, dev_socket_id;
    uint8_t port;
    struct rte_mbuf *pkts[MAX_RX_BURST_SIZE * 2];
    const int attempts = 0;
    struct rte_mbuf *m;

    struct rte_mempool *header_pool;
    struct rte_mempool *clone_pool;
    struct rte_ring **output_rings = params->output_rings;

    header_pool = rte_pktmbuf_pool_create("header_pool", NB_HDR_MBUF,
            CLONEPOOL_CACHE_SIZE, 0, 2 * RTE_PKTMBUF_HEADROOM,
            rte_socket_id());
    assert(header_pool != NULL);

    clone_pool = rte_pktmbuf_pool_create("clone_pool", NB_CLONE_MBUF,
            CLONEPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_socket_id());
    assert(clone_pool != NULL);


    LOG_INFO(
        USER1,
        "Receive worker started; core=%u, socket=%u, queue=%u attempts=%d \n",
        rte_lcore_id(), socket_id, queue_id, attempts);

    // validate each port
    for (port = 0; port < nb_ports; port++)
    {
        // skip ports that are not enabled
        if ((params->enabled_port_mask & (1 << port)) == 0)
        {
            printf("skipping port: %d\n", port);
            continue;
        }

        // check for cross-socket communication
        dev_socket_id = rte_eth_dev_socket_id(port);
        if (dev_socket_id >= 0 && ((unsigned)dev_socket_id) != socket_id)
        {
            LOG_WARN(USER1,
                     "Warning: Port %u on different socket from worker; "
                     "performance will suffer\n",
                     port);
        }
    }

    port = params->port_id;
    while (!quit_signal)
    {
        // skip to the next enabled port
        if ((params->enabled_port_mask & (1 << port)) == 0)
        {
            if (++port == nb_ports)
            {
                port = 0;
            }
            continue;
        }

        // receive a 'burst' of packets. if get back the max number requested,
        // then there are likely more packets waiting. immediately go back and
        // grab some. Zhang: the while condition may cause initial delay.
        i = 0;
        uint16_t nb_in = 0, nb_in_last = 0, nb_out = 0;
        do
        {
            nb_in_last =
                rte_eth_rx_burst(port, queue_id, &pkts[nb_in], rx_burst_size);
            nb_in += nb_in_last;

        } while (++i < attempts && nb_in_last == rx_burst_size);
        params->stats.in += nb_in;

        // add each packet to the ring buffer
        if (likely(nb_in) > 0)
        {
            // enqueue to acl ring
            //printf("got %d packets\n", nb_in);


            for (unsigned j = 0; j < nb_in; j++) {
                m = pkts[j];
				mrtom_process(m, header_pool, clone_pool, output_rings);
			}
            //nb_out = rte_eth_tx_burst(0,0,pkts, nb_in);
            //nb_out =
            //    rte_ring_enqueue_bulk(output_ring, (void *)pkts, nb_in, NULL);
            //printf("sent %d packets\n", nb_out);
            
            params->stats.out += nb_out;
            params->stats.drops += (nb_in - nb_out);
            //params->stats.ring_space = rte_ring_free_count(output_ring);
        }

        // wrap-around to the first port
        if (++port == nb_ports)
        {
            port = 0;
        }
    }

    LOG_INFO(USER1, "Receive worker finished; core=%u, socket=%u, queue=%u \n",
             rte_lcore_id(), socket_id, queue_id);
    return 0;
}




/*
 * Start the receive and transmit works.
 */
int start_workers(rx_worker_params *rx_params, 
                  mrtom_worker_params *mrtom_params,
                  struct rte_ring **mrtom_rings,
                  app_params *p)
{
    unsigned lcore_id;
    unsigned rx_worker_id = 0;
    unsigned mrtom_worker_id = 0;
    signal(SIGINT, sig_handler);

    // launch the workers
    // RX worker should launch last, to avoid ongoing
    // telemetry packet bombarding pipelines that are not fully initialized.
    RTE_LCORE_FOREACH_SLAVE(lcore_id)
    {
        if (rx_worker_id < p->nb_rx_workers)
        {
            // start RX-workers

            LOG_INFO(USER1,
                     "Launching receive worker; worker=%u, core=%u, queue=%u\n",
                     rx_worker_id, lcore_id, rx_worker_id);
            rx_params[rx_worker_id] =
                (rx_worker_params){.worker_id = rx_worker_id,
                                   .queue_id = 0,
                                   .rx_burst_size = MAX_RX_BURST_SIZE,
                                   .enabled_port_mask = p->enabled_port_mask,
                                   .output_rings = mrtom_rings,
                                   .nb_ports = NUM_PORTS,
                                   .port_id = rx_worker_id,
                                   .stats = {0}};
            rte_eal_remote_launch((lcore_function_t *)receive_worker,
                                  &rx_params[rx_worker_id], lcore_id);
            rx_worker_id++;
        }
        else if (mrtom_worker_id < p->nb_tx_workers)
        {
            LOG_INFO(USER1,
                     "Launching mrtom tx worker; worker=%u, core=%u, queue=%u\n",
                     mrtom_worker_id, lcore_id, mrtom_worker_id);
            mrtom_params[mrtom_worker_id] =
                (mrtom_worker_params){.worker_id = mrtom_worker_id,
                                   .rx_burst_size = MAX_RX_BURST_SIZE,
                                   .tx_port = 0,
                                   .input_ring = mrtom_rings[mrtom_worker_id],
                                   .stats = {0}};
            rte_eal_remote_launch((lcore_function_t *)mrtom_worker,
                                  &mrtom_params[mrtom_worker_id], lcore_id);
            mrtom_worker_id++;
        }
        
    }

    return 0;
}



/*
 * Monitors the receive and transmit workers.  Executed by the main thread,
 * while other threads are created to perform the actual packet processing.
 */
int monitor_workers(rx_worker_params *rx_params, const unsigned nb_rx_workers,
                    mrtom_worker_params *mrtom_param, const unsigned nb_tx_workers
                    
                    )
{
    sleep(1);

    

    /*
     * Start the busy loop
     */

    LOG_INFO(USER1, "Starting to monitor workers; core=%u, socket=%u \n",
             rte_lcore_id(), rte_socket_id());
    while (!quit_signal)
    {
        print_stats(rx_params, nb_rx_workers, mrtom_param, nb_tx_workers);
        
        //rte_eth_dev_statss();
        sleep(1);
    }
    
    
    LOG_INFO(USER1, "Finished monitoring workers; core=%u, socket=%u \n",
             rte_lcore_id(), rte_socket_id());
    return 0;
}
