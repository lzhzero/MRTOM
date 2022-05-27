/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

//paxos related
#define NOPAXOS_MSG_REQUEST 1
#define NOPAXOS_MSG_REPLY 2
#define NOPAXOS_MSG_OTHE 255
//#define MAX_REPLICA_GROUPS 65536

#define SESSION_ID 0;
#define NR_GROUPS 1;
#define NOPAXOS_IP 0xc0a800ff
//192.168.0.255
#define RECIR_IP  0x1010101
//16.16.16.16
#define MAX_ROM_WINDOW 16777216
#define NUM_REPLICA 3
#define NUM_FAILS 1
#define PAXOS_BITMASK 0b00111
#define PAXOS_LEADER_MASK 0b10000
#define PAXOS_DEFAULT_MASK 0x7F

#define CLIENT_IP1 0xc0a8006f
//192.168.0.111
#deinfe CLIENT_ID1 0x1


#define PAXOS_PORT1 178
#define PAXOS_IP1 0xc0a80070
//192.168.0.112
#define PAXOS_P1_MASK 0xE
				//    ~0b001
#define PAXOS_PORT2 136
#define PAXOS_IP2 0Xc0a80071
//192.168.0.113
#define PAXOS_P2_MASK 0xD
				//	  ~0b010
#define PAXOS_PORT3 162
#define PAXOS_IP3 0Xc0a80072
//192.168.0.114
#define PAXOS_P3_MASK 0xB
				//	  ~0b100

#define PAXOS_RECIR_LIMIT 3
//#define RECIR_PORT2 68  this is pipe0 recir port
//#define RECIR_PORT 32		this is pipe0 recir port too
//#define RECIR_PORT_IN 48

#define RECIR_PORT 196

// Delta_T unit is 2^28 ns ~= 0.268s, see code for detailed comments.
#define RECIR_DELTA_T 0b100
#define REG_SET  0b1
#define REG_UPDATE  0b10
const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<16> ARP_OPCODE_REQUEST   = 1;
const bit<16> ARP_OPCODE_REPLY     = 2;

struct metadata_t {
	ipv4_addr_t arp_dst_ipv4;
	udp_port_t udp_src_port;
	ip_protocol_t protocol;
    bit<16> reg_record_out;
	bit<16> reg_pt;
	bit<16> ROM_bitmask;
	bool request_success_flag;
	bool drop_flag;
	bit<16> msg_count;
	bit<32> clientreqid;
	bit<16> random;
//	ipv4_addr_t dst_ipv4;
//	mac_addr_t dst_mac;

	 
}




// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
		ig_md.arp_dst_ipv4 = 0x0;
		ig_md.udp_src_port = 0x0;
		ig_md.protocol = 0x0;
		ig_md.reg_record_out = 0x0;
		ig_md.reg_pt = 0x0;
		ig_md.ROM_bitmask = 0x0;
		ig_md.request_success_flag = false;
		ig_md.drop_flag = false;
		ig_md.msg_count = 0x0;
		ig_md.clientreqid = 0x0;
		ig_md.random = 0x0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
//		ig_md.dst_mac = hdr.ethernet.dst_addr;
        transition select(hdr.ethernet.ether_type){
			ETHERTYPE_IPV4	:	parse_ipv4;
			ETHERTYPE_ARP	:	parse_arp;
			default			:	accept;
		}

    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
//		ig_md.dst_ipv4 = hdr.ipv4.dst_addr;
        transition select(hdr.ipv4.protocol){
			IP_PROTOCOLS_ICMP			:   parse_icmp;
			IP_PROTOCOLS_UDP			:   parse_udp;
			default                 	:   accept;
		}
    }
	state parse_icmp {
		pkt.extract(hdr.icmp);
		transition accept;
	}

	state parse_udp {
		pkt.extract(hdr.udp);
//		ig_md.udp_src_port = hdr.udp.dst_port;
		transition select(hdr.udp.dst_port, hdr.udp.src_port){
			(UDP_NOPAXOS_PORT,_)			:	parse_nopaxos;
			(_,UDP_NOPAXOS_PORT)			:	parse_nopaxos;
			default						:	accept;
		}
	}

    state parse_nopaxos {
        pkt.extract(hdr.nopaxos);
        transition select(hdr.nopaxos.msg_type){
            NOPAXOS_REQUEST             :   parse_nopaxos_request;
            default                     :    accept;
        }
    }

    state parse_nopaxos_request {
        pkt.extract(hdr.nopaxos_request);
        transition accept;
    }

	state parse_arp {
		pkt.extract(hdr.arp);
		transition select(hdr.arp.hw_type, hdr.arp.proto_type){
			(ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4)	:	parse_arp_ipv4;
			default									:	accept;
		}
	}
	state parse_arp_ipv4 {
		pkt.extract(hdr.arp_ipv4);
		ig_md.arp_dst_ipv4 = hdr.arp_ipv4.dst_proto_addr;
		transition accept;
	}


}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Checksum<>() ipv4_checksum;
//	Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});

         pkt.emit(hdr);
    }
}



control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {


/************************************************************
*   sequencer registers
*	each register is limited to 32bit output
*	reg_seq_lo and reg_seq_hi are combined to make 64bit registers
**************************************************************/
    Register<bit<32>, _>(32w1) reg_seq_lo;
    RegisterAction<bit<32>,_,bit<32>>(reg_seq_lo) reg_seq_lo_increment = {
        void apply(inout bit<32> state, out bit<32> output_lo){
            state = state + 1;
            output_lo = state;
        }
    };

    Register<bit<32>, _>(32w1) reg_seq_hi;
    RegisterAction<bit<32>,_,bit<32>>(reg_seq_hi) reg_seq_hi_increment = {
        void apply(inout bit<32> state, out bit<32> output_hi){
            state = state + 1;
            output_hi = state;
        }
    };
    RegisterAction<bit<32>,_,bit<32>>(reg_seq_hi) reg_seq_hi_read = {
        void apply(inout bit<32> state, out bit<32> output_hi){
            output_hi = state;
        }
	};

/************************************************************
*   msg counter  registers
*   this is used to keep track of how many messages received.
*   may not be necessary since reg_record contains such info
**************************************************************/
    Register<bit<16>,bit<24>>(65536) reg_count;

    RegisterAction<bit<16>, bit<24>, bit<16>>(reg_count) reg_count_set = {
        void apply(inout bit<16> record, out bit<16> output){
				record = NUM_REPLICA;
                output = record;
        }
    };
    RegisterAction<bit<16>, bit<24>, bit<16>>(reg_count) reg_count_down = {
        void apply(inout bit<16> record, out bit<16> output){
            record = record - 1;
            output = record;
        }
    };

/************************************************************
*   main register for managing nopaxos
**************************************************************/
    Register<bit<16>,bit<16>>(65536) reg_record;

    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_record) reg_set = {
        void apply(inout bit<16> record, out bit<16> output){
                record = ig_md.ROM_bitmask;
                output = 1;
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_record) reg_update = {
        void apply(inout bit<16> record, out bit<16> output){
            record = record & ig_md.ROM_bitmask;
            output = record;
        }
    };

/************************************************************
*   register for keep track of clientreqid for each client.
*	This is used to makes older server respond are not used
**************************************************************/
    Register<bit<32>,bit<16>>(65536) reg_clientreqid;

    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_clientreqid) clientreqid_update = {
        void apply(inout bit<32> record, out bit<32> output){
                record = ig_md.clientreqid;
                output = 1;
        }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_clientreqid) clientreqid_read = {
        void apply(inout bit<32> record, out bit<32> output){
            output = record;
        }
    };



/************************************************************
*   forward table is used to lookup dst_mac and route to the correct port
**************************************************************/
    action hit(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action miss(bit<3> drop) {
        ig_dprsr_md.drop_ctl = drop; // Drop packet.
    }

    table forward {
        key = {
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            hit;
//            @defaultonly miss;
            miss;
        }
        size = 1024;
    }




/************************************************************
*   arping is use to automatically reply arp messages without broadcast
**************************************************************/
	action send_arp_reply(mac_addr_t dst_mac){
		hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
		hdr.ethernet.src_addr = dst_mac;

		hdr.arp.opcode = ARP_OPCODE_REPLY;
		hdr.arp_ipv4.dst_hw_addr = hdr.arp_ipv4.src_hw_addr;
		hdr.arp_ipv4.dst_proto_addr = hdr.arp_ipv4.src_proto_addr;
		hdr.arp_ipv4.src_hw_addr = dst_mac;
		hdr.arp_ipv4.src_proto_addr = ig_md.arp_dst_ipv4;
	}
	table  arping {
		key = {
			ig_md.arp_dst_ipv4 		: exact;
			hdr.arp.opcode			: exact;

		}
		actions = {
			send_arp_reply;
			miss;
		}
		size = 100;
		const default_action = miss(0x1);

	}



/************************************************************
*	t_reg_op2 is use to assign actions based on t_reg_op output 
**************************************************************/
	action request_failed(){
		//run out of registers, too many pending request/recirculated packets
		//should send error message to client, but can also do nothing
		ig_md.drop_flag = true;
	}
	action request_success(){
		ig_md.request_success_flag = true;
	}
	action respond_to_client(){
		//do nothing, let the packet pass
	}
	action do_not_respond(){
			//drop the packet if no need to send to client
			ig_md.drop_flag = true;
	}
    table t_reg_op2 {
        key = {
            hdr.nopaxos.msg_type       	:   exact;
			hdr.nopaxos.is_leader		:	exact;
            ig_md.reg_record_out    	:   exact;
        }
        actions = {
			request_failed;
			request_success;
			respond_to_client;
			do_not_respond;
        }
        const entries = {
            (NOPAXOS_MSG_REQUEST,      	16w0,		0	)	:   request_failed();
            (NOPAXOS_MSG_REQUEST,      	16w0,		1	)	:   request_success();
            (NOPAXOS_MSG_REPLY,			16w1,		0b0)  	:   respond_to_client();
            (NOPAXOS_MSG_REPLY,			16w1,		0b001)  :   respond_to_client();
            (NOPAXOS_MSG_REPLY,			16w1,		0b010)  :   respond_to_client();
            (NOPAXOS_MSG_REPLY,			16w1,		0b100)  :   respond_to_client();
            (NOPAXOS_MSG_REPLY,			16w0,		0b001)  :   respond_to_client();
            (NOPAXOS_MSG_REPLY,			16w0,		0b010)  :   respond_to_client();
            (NOPAXOS_MSG_REPLY,			16w0,		0b100)  :   respond_to_client();
   //         (IP_PROTOCOLS_RECIR_LAST,   	0)  :   recir_check_done();
   //         (IP_PROTOCOLS_RECIR_LAST,   	 )  :   recir_check_not_done();

        }
		const default_action = do_not_respond;
        size = 256;

    }
/************************************************************
*	t_reg_op is use to update register reg_record,
*	it keeps track of client request
**************************************************************/
    action reg_op_set(){
//		reg_count_set.execute(ig_md.reg_pt);
//        ig_md.reg_record_out = reg_set.execute(ig_md.reg_pt[15:0]);
        ig_md.reg_record_out = reg_set.execute(ig_md.reg_pt);
    }
    action reg_op_update(){
//		ig_md.msg_count = reg_count_down.execute(ig_md.reg_pt);
//        ig_md.reg_record_out  = reg_update.execute(ig_md.reg_pt[15:0]);
        ig_md.reg_record_out  = reg_update.execute(ig_md.reg_pt);
    }
    table t_reg_op {
        key = {
            hdr.nopaxos.msg_type : exact;
        }
        actions = {
            reg_op_set;
            reg_op_update;
        }
        const entries = {
            (NOPAXOS_MSG_REQUEST)          : reg_op_set();
            (NOPAXOS_MSG_REPLY)			   : reg_op_update();
        //    (IP_PROTOCOLS_RECIR_LAST)       : reg_op_update();
        //  (IP_PROTOCOLS_RECIR)            : reg_op_update();
            }
        size = 16;
    }
/************************************************************
*   t_clientreqid  is used to make sure older server responds are dropped.
*	used together with reg_clientreqid
*	For request message, clientreq_update is called
*	For respond message, clientreq_read is called
**************************************************************/
	action action_clientreqid_update(){
		clientreqid_update.execute(ig_md.reg_pt);
	}

	action action_clientreqid_read(){
		ig_md.clientreqid = clientreqid_read.execute(ig_md.reg_pt);
	}

	table t_clientreqid {
		key = {
			hdr.nopaxos.msg_type	: exact;
		}
		actions = {
			action_clientreqid_update;
			action_clientreqid_read;
		}
		const entries = {
			(NOPAXOS_MSG_REQUEST)		:	action_clientreqid_update();
			(NOPAXOS_MSG_REPLY)			:	action_clientreqid_read();
		}
		size = 16;
	}


/************************************************************
*	t_paxos is the Main Paxos table, deal with all kinds of packets with actions	
*	RIGHT NOW, THIS TABLE DOES NOTHING
**************************************************************/
    action paxos_request(){
		hdr.nopaxos_request.orig_udp_src  = hdr.udp.src_port;
			//timestamping, currently no place in header yet!
			//hdr.nopaxos.ig_prsr_timestamp = ig_prsr_md.global_tstamp;
	}
	action paxos_recir(){
		//update the delta_T for recir time
		//ig_md.delta_t  = ig_prsr_md.global_tstamp - hdr.nopaxos.ig_prsr_timestamp;
		//ig_md.delta_t4 = (bit<4>) ig_md.delta_t[31:28];
	}
    table t_paxos {
        key = {
            hdr.nopaxos.msg_type   : exact;
        }
        actions = {
            paxos_request;
//          paxos_respond;
            paxos_recir;
//          paxos_recir_last;
        }
        const entries = {
            (NOPAXOS_MSG_REPLY)	   	: paxos_request();
//            (NOPAXOS_MSG_RECIR)   	: paxos_recir();
        }
        size = 16;
    }

/************************************************************
*	t_paxos_assign_bm table, used to assign bitmask to flip registers for each request.
*	it will mask respond packet from servers, and also recir packet
*****************************************************************/
    action assign_bitmap_request(bit<16> bitmask){
        ig_md.reg_pt[7:0] = hdr.udp.src_port[7:0];
		ig_md.reg_pt[15:8] = hdr.ipv4.src_addr[7:0];
        ig_md.ROM_bitmask = bitmask;
		ig_md.clientreqid = hdr.nopaxos.clientreqid[31:0];
    }
    action assign_bitmap_reply_leader(bit<16> bitmask){
        ig_md.reg_pt[7:0] = hdr.udp.dst_port[7:0];
		ig_md.reg_pt[15:8] = hdr.ipv4.dst_addr[7:0];
		ig_md.ROM_bitmask = bitmask;
		ig_md.clientreqid = hdr.nopaxos.clientreqid[31:0];
    }
    action assign_bitmap_reply_follower(bit<16> bitmask){
        ig_md.reg_pt[7:0] = hdr.udp.dst_port[7:0];
		ig_md.reg_pt[15:8] = hdr.ipv4.dst_addr[7:0];
       	ig_md.ROM_bitmask = bitmask;
		ig_md.clientreqid = hdr.nopaxos.clientreqid[31:0];
    }
    table t_paxos_assign_bm {
        key = {
            hdr.ipv4.src_addr			:   ternary;
            hdr.nopaxos.msg_type		:   exact;
			hdr.nopaxos.is_leader		:	ternary;
        }
        actions = {
            assign_bitmap_request;
            assign_bitmap_reply_follower;
            assign_bitmap_reply_leader;
        }
        const entries = {
            (PAXOS_IP1,		NOPAXOS_MSG_REPLY,		16w0)   : assign_bitmap_reply_follower(PAXOS_P1_MASK + PAXOS_LEADER_MASK);
            (PAXOS_IP2,		NOPAXOS_MSG_REPLY,		16w0)	: assign_bitmap_reply_follower(PAXOS_P2_MASK + PAXOS_LEADER_MASK);
            (PAXOS_IP3,		NOPAXOS_MSG_REPLY,		16w0)	: assign_bitmap_reply_follower(PAXOS_P3_MASK + PAXOS_LEADER_MASK);
            (PAXOS_IP1,		NOPAXOS_MSG_REPLY,		16w1)   : assign_bitmap_reply_leader(PAXOS_P1_MASK);
            (PAXOS_IP2,		NOPAXOS_MSG_REPLY,		16w1)	: assign_bitmap_reply_leader(PAXOS_P2_MASK);
            (PAXOS_IP3,		NOPAXOS_MSG_REPLY,		16w1)   : assign_bitmap_reply_leader(PAXOS_P3_MASK);
            (_,				NOPAXOS_MSG_REQUEST,	_)    	: assign_bitmap_request(PAXOS_BITMASK + PAXOS_LEADER_MASK);
         
        }
        size = 8;
    }

/***************************************************************
*	t_protocol is used to identify the type of messages
**************************************************************/

	Random<bit<16>>() ran;

/***************************************************************
*	apply block
**************************************************************/
    apply {
		// drop ICMP unreachable message type 3
		ig_md.random = ran.get();
		if(hdr.icmp.isValid() && hdr.icmp.type_ == 3){
			ig_dprsr_md.drop_ctl = 0x1;
			return;
		}
		// apply arp table
        if(hdr.arp.isValid()){
			arping.apply();
		}
		else if(hdr.nopaxos.isValid() ){// UDP port 11111 identified.
		//process all no paxos related packets

			// hdr.nopaxos.msg_type stores nopaxos message type
//			if(hdr.nopaxos.msg_type == NOPAXOS_MSG_REQUEST || hdr.nopaxos.msg_type == NOPAXOS_MSG_REPLY){

			//	assign bit_map for nopaxos respond packet
			t_paxos_assign_bm.apply();

			t_clientreqid.apply();
			if(hdr.nopaxos.msg_type == NOPAXOS_MSG_REPLY)
				if(hdr.nopaxos.clientreqid[31:0] != ig_md.clientreqid){
					//early drop
					ig_dprsr_md.drop_ctl = 0x1;
					return;
				}			

			t_paxos.apply();
			if(t_reg_op.apply().hit){
				t_reg_op2.apply();
			}
			if(ig_md.drop_flag){
				ig_dprsr_md.drop_ctl = 0x1;
				return;
			}
			else if(ig_md.request_success_flag){
				//do multicast here
				//process nopaxos packet and do multicast
		//		hdr.udp.src_port = 0x1;
				hdr.udp.checksum = 0x0;
			// updated in t_paxos table action already
				hdr.nopaxos_request.orig_udp_src = hdr.udp.src_port;
				hdr.udp.src_port = 0x1;
				hdr.nopaxos_request.session_id = SESSION_ID;
				hdr.nopaxos_request.nr_groups = NR_GROUPS; //currently nr_groups == 1
				hdr.nopaxos_request.gr_id = 0x0;
				hdr.nopaxos_request.gr_sequence[31:0] = reg_seq_lo_increment.execute(32w0);
				if(hdr.nopaxos_request.gr_sequence[31:0] == 0x0)
					hdr.nopaxos_request.gr_sequence[63:32] = reg_seq_hi_increment.execute(32w0);
				else
					hdr.nopaxos_request.gr_sequence[63:32] = reg_seq_hi_read.execute(32w0);
				//	ig_tm_md.bypass_egress = TRUE;
				ig_tm_md.mcast_grp_a = 0x1;
			}
			else if(hdr.nopaxos.msg_type == NOPAXOS_MSG_REPLY){
				//roll dice here
//				if(ig_md.random <= 655){//1%
//					ig_dprsr_md.drop_ctl = 0x1;
//					return;
//				}
			}

		}
		else
			ig_tm_md.bypass_egress = TRUE;//0x1;
		
		//apply forward table
		forward.apply();

	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

	/***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
}

	/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

	/***********************  P A R S E R  **************************/

parser SwitchEgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control SwitchEgress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    action modify_packet_no_vlan(bit<48> dstmac, bit<32> dstip) {
        hdr.ethernet.dst_addr = dstmac;
        hdr.ipv4.dst_addr     = dstip;
    }

    table mcast_mods {
        key = {
            eg_intr_md.egress_rid   :   exact; //Single Mcast with hardcoded RID=5
            eg_intr_md.egress_port  :   exact;
        }
        actions = {
            modify_packet_no_vlan;
            NoAction;
        }
		const default_action = NoAction;
        size = 4096;
    }

    apply {
        mcast_mods.apply();

        //process incoming recir packet modify protocol ID once
//        if(eg_intr_md.egress_port == RECIR_PORT && hdr.ipv4.isValid() && hdr.ipv4.protocol == IP_PROTOCOLS_NOPAXOS)
//            hdr.ipv4.protocol = IP_PROTOCOLS_RECIR;

    }
}

    /*********************  D E P A R S E R  ************************/

control SwitchEgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
	Checksum<>() ipv4_checksum;
//	Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;
    apply {
		if (hdr.ipv4.isValid()) {
			hdr.ipv4.hdr_checksum = ipv4_checksum.update({
				hdr.ipv4.version,
				hdr.ipv4.ihl,
				hdr.ipv4.diffserv,
				hdr.ipv4.total_len,
				hdr.ipv4.identification,
				hdr.ipv4.flags,
				hdr.ipv4.frag_offset,
				hdr.ipv4.ttl,
				hdr.ipv4.protocol,
				hdr.ipv4.src_addr,
				hdr.ipv4.dst_addr
			});
		}
		pkt.emit(hdr);
	}
}


/************ F I N A L   P A C K A G E ******************************/



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
