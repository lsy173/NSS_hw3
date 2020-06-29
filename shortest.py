from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
# from ryu.controller import network
from ryu.ofproto import ofproto_v1_3
import networkx as nx
from collections import defaultdict

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

DEFAULT_TIMEOUT = 10

class Shortest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(Shortest, self).__init__(*args, **kwargs)
        self.net = nx.DiGraph()
        self.dp_host_ports = defaultdict(list)
        self.arp_table = dict()
        self.dpid_to_dp = dict()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                    idle_timeout=idle_timeout, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        buffer_id = msg.buffer_id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        dpid = dp.id

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port)
            self.net.add_edge(src, dpid)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            pkt_arp = pkt.get_protocol(arp.arp)
            pkt_edpith = pkt.get_protocol(ethernet.ethernet)
            self.arp_table[pkt_arp.src_ip] = src  # ARP learning
            if pkt_arp.opcode == arp.ARP_REQUEST and pkt_arp.dst_ip in self.arp_table:
                reply_mac = self.arp_table[pkt_arp.dst_ip]
                e = ethernet.ethernet(pkt_eth.src, reply_mac, ether_types.ETH_TYPE_ARP)
                a = arp.arp(opcode=arp.ARP_REPLY, src_mac=reply_mac, src_ip=pkt_arp.dst_ip,
                        dst_mac=pkt_eth.src, dst_ip=pkt_arp.src_ip)

                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()

                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT)]
                out = dp.ofproto_parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port,
                    actions=actions, data=p.data
                )
                dp.send_msg(out)
            else:
                # ARPs are sent to the edge ports
                dst = pkt_eth.dst
                src = pkt_eth.src
                dpid = dp.id

                self.flood_to_edges(msg)

            return

        if dst in self.net:
            spath = nx.shortest_path(self.net, src, dst)
            next_hop = spath[spath.index(dpid)+1]
            out_port = self.net[dpid][next_hop]['port']
            shortest_path_log = ' -> '.join([str(x) for x in spath])
            print("from {} to {} hop = {}, path {}".format(src, dst, len(spath)-1, shortest_path_log))
        else:
            self.flood_to_edges(msg)
            return

        actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
        match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

        self.add_flow(dp, 1, match, actions, DEFAULT_TIMEOUT, msg.buffer_id)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data
        )
        dp.send_msg(out)

    def flood_to_edges(self, msg):
        for dpid in self.dpid_to_dp:
            ports = self.dp_host_ports[dpid]
            dp = self.dpid_to_dp[dpid]
            for port_no in ports:
                actions = [dp.ofproto_parser.OFPActionOutput(port_no)]    
                out = dp.ofproto_parser.OFPPacketOut( in_port=dp.ofproto.OFPP_CONTROLLER,
                    datapath=dp, actions=actions, data=msg.data, buffer_id=dp.ofproto.OFP_NO_BUFFER
                )
                dp.send_msg(out)

    @set_ev_cls([event.EventSwitchLeave, event.EventSwitchEnter, event.EventLinkAdd])
    def get_topology_data(self, ev):
        switch_list = get_switch(self, None)
        switches=[switch.dp.id for switch in switch_list]
        for sw in switch_list:
            self.dpid_to_dp[sw.dp.id] = sw.dp

        self.net.add_nodes_from(switches)
        links_list = get_link(self, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        
        self.dp_host_ports = defaultdict(list)
        
        for sw in switch_list:
            for p in sw.ports:
                self.dp_host_ports[sw.dp.id].append(p.port_no)

        srcset = set([(link.src.dpid, link.src.port_no) for link in links_list])
        dstset = set([(link.dst.dpid, link.dst.port_no) for link in links_list])
        for dpid, port in (srcset | dstset):
            if port in self.dp_host_ports[dpid]:
                idx = self.dp_host_ports[dpid].index(port)
                del self.dp_host_ports[dpid][idx]

