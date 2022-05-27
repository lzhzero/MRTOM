
#ifndef HT_HEADER_H
#define HT_HEADER_H

//#include <rte_common.h>
#include <rte_byteorder.h>

struct rte_paxos_hdr {
	rte_be32_t frag_magic;
	rte_be16_t msg_type;
	uint8_t recir_counter;
	uint8_t padding1;

	rte_be16_t padding2;
	rte_be16_t timestamp1;
	rte_be32_t timestamp2;
	
	rte_be64_t view;
	rte_be16_t is_leader;
	rte_be16_t reserved1;
	rte_be32_t reserved2;
	rte_be64_t clientreqid;
	
	rte_be64_t msgnum;
	rte_be64_t clientid;
	rte_be16_t op_code;
	rte_be16_t padding3;
	rte_be32_t padding4;

	rte_be64_t ops;

} __attribute__((__packed__));

struct rte_paxos_request_hdr {
	rte_be32_t hdr_len;
	rte_be16_t orig_udp_src;
	rte_be16_t padding;
	rte_be64_t session_id;
	rte_be32_t nr_groups;
	rte_be32_t gr_id;
	rte_be64_t gr_sequence;

} __attribute__((__packed__));

#endif // HT_HEADER_H
