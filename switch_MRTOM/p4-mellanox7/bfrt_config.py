#sm114-sm115 netronome 40G enps0np0 direct connect
#sm115 on 40G port 13/-
#bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0x00154d133dc6, port=156)
#sm116 on 40G port 16/-
#bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0x00154d133db4, port=172)
#sm117 on 40G port 15/-
#bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0x00154d133d12, port=188)
#sm118 on 40G port 14/-
#bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0x00154d133dbd, port=140)

#sm111 on 10G port 
bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0xe41d2d1e1ec0, port=138)
#sm112 on 10G port 
bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0xe41d2d1e1ee0, port=178)
#sm113 on 10G port 
bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0xe41d2d1e21a0, port=136)
#sm114 on 10G port 
bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0xe41d2d1e1ef0, port=162)
#sm115 on 10G port 
bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0xe41d2d1e21e0, port=176)
#sm116 on 10G port 
bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0xe41d2d1e2ad0, port=146)
#sm117 on 10G port 
bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0xe41d2d1e1eb0, port=144)
#sm118 on 10G port 
bfrt.nopaxos_p4_7.pipe.SwitchIngress.forward.add_with_hit(dst_addr=0xe41d2d1e1d50, port=160)


#sm115 on 40G port 13/-
#bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.115', opcode=0x1,dst_mac=0x00154d133dc6)
#sm116 on 40G port 16/-
#bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.116', opcode=0x1,dst_mac=0x00154d133db4)
#sm117 on 40G port 15/-
#bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.117', opcode=0x1,dst_mac=0x00154d133d12)
#sm118 on 40G port 14/-
#bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.118', opcode=0x1,dst_mac=0x00154d133dbd)

bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.111', opcode=0x1,dst_mac=0xe41d2d1e1ec0)
bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.112', opcode=0x1,dst_mac=0xe41d2d1e1ee0)
bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.113', opcode=0x1,dst_mac=0xe41d2d1e21a0)
bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.114', opcode=0x1,dst_mac=0xe41d2d1e1ef0)
bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.115', opcode=0x1,dst_mac=0xe41d2d1e21e0)
bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.116', opcode=0x1,dst_mac=0xe41d2d1e2ad0)
bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.117', opcode=0x1,dst_mac=0xe41d2d1e1eb0)
bfrt.nopaxos_p4_7.pipe.SwitchIngress.arping.add_with_send_arp_reply(arp_dst_ipv4='192.168.0.118', opcode=0x1,dst_mac=0xe41d2d1e1d50)

#bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=156, dstmac= 0x00154d133d12, dstip='192.168.0.1')
#bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=172, dstmac= 0x00154d133dbd, dstip='192.168.0.2')
#bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=188, dstmac= 0x00154d133db4, dstip='192.168.0.3')
#bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=140, dstmac= 0x00154d133dcf, dstip='192.168.0.4')
bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=178, dstmac= 0xe41d2d1e1ee0, dstip='192.168.0.112')
bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=136, dstmac= 0xe41d2d1e21a0, dstip='192.168.0.113')
bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=162, dstmac= 0xe41d2d1e1ef0, dstip='192.168.0.114')
bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=176, dstmac= 0xe41d2d1e21e0, dstip='192.168.0.115')
bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=146, dstmac= 0xe41d2d1e2ad0, dstip='192.168.0.116')
bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=144, dstmac= 0xe41d2d1e1eb0, dstip='192.168.0.117')
bfrt.nopaxos_p4_7.pipe.SwitchEgress.mcast_mods.add_with_modify_packet_no_vlan(egress_rid=5, egress_port=160, dstmac= 0xe41d2d1e1d50, dstip='192.168.0.118')

