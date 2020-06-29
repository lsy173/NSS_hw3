from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_3
import networkx as nx
from collections import defaultdict
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import in_proto

DEFAULT_TIMEOUT = 10

class Nettap(app_manager.RyuApp):
   OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
   def __init__(self, *args, **kwargs):
       super(Nettap, self).__init__(*args, **kwargs)
       self.net = nx.DiGraph()
       self.iport = defaultdict(dict)
       self.taphost = "00:00:00:00:00:01"

   @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
   def switch_features_handler(self, ev):
       msg = ev.msg
       datapath = msg.datapath
       ofproto = datapath.ofproto
       parser = datapath.ofproto_parser
       match = parser.OFPMatch()
       actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

       self.add_flow(datapath, 0, match, actions)

   def add_flow(self, datapath, priority, match, actions, idle_timeout=0, buffer_id=None):
       ofproto = datapath.ofproto
       parser = datapath.ofproto_parser

       instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

       if buffer_id:
          mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, idle_timeout=idle_timeout, instructions=instructions)
       else:
          mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, idle_timeout=idle_timeout, instructions=instructions)

       datapath.send_msg(mod)

   @set_ev_cls(ofp_event.EventOFPPacketInt, MAIN_DISPATCHER)
   def packet_in_handler(self, ev):
       msg = ev.msg
       datapath = msg.datapath
       ofproto = datapath.ofproto
       parser = datapath.ofproto_parser
       in_port = msg.match['in_port']
       buffer_id = msg.buffer_id
       pkt = packet.Packet(msg)
       eth = pkt.get_protocol(ethernet.ethernet)
      
       dst = eth.dst
       src = eth.src
       dpid = datapath.id

       if eth.ethertype == ethertype_LLDP:
          # ignore lldp packet
          return 

       if src not in self.net:
          self.net.add_node(src)
          self.net.add_edge(dpid, src, port=in_port)
          self.net.add_edge(src, dpid)
          
       if self.taphost in self.net and dst in self.net:
          out_ports = list()

          spath = nx.shortest_path(self.net, src, dst)
          if dpid in spath:
             shortest_next_hop = spath[spath.index(dpid)+1]
             shortest_out_port = self.net[dpid][shortest_next_hop]['port']
             out_ports.append(shortest_out_port)

          if self.taphost != dst and self.taphost != src:
             tap_path = nx.shortest_path(self.net, src, self.taphost)
             if dpid in tap_path:
                tap_next_hop = tap_path[tap_path.index(dpid)+1]
                tap_out_port = self.net[dpid][tap_next_hop]['port']
                out_ports.append(tap_out_port)

          if dpid in spath:
             actions = [parser.OFPActionOutput(shotest_out_port)]
             match = parser.parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
             
          if len(out_ports) >= 1:
             # In other case, simple switch will do the job
             tap_actions = [parser.OFPActionOutput(x) for x in set(out_ports)]
             src_match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=0x0800, ip_proto=6, tcp_src=80)
             self.add_flow(datapath, 2, src_match, tap_actions, DEFAULT_TIMEOUT)

             data = None
             if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
 
             out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=tap_actions, data=data)
             datapath.set_msg(out)
    
       else:
             out_port = ofproto.OFPP_FLOOD
             actions = [parser.OFPActionOutput(out_port)]
             match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
 
             data = None
             if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
 
             out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
             datapath.send_msg(out)

   @set_ev_cls([event.EventLinkAdd, event.EventLinkDelete])
   def link_handler(self, ev):
       if isinstance(ev, event.EventLinkAdd):
          self.logger.info("link %s -> %s, port_no: %s added", ev.link.src.dpid, ev.link.dst.dpid, ev.link.src.port_no)
          self.logger.info("link %s -> %s, port_no: %s added", ev.link.dst.dpid, ev.link.src.dpid, ev.link.dst.port_no)
          self.net.add_edge(ev.link.src.dpid, ev.link.dst.dpid, port=ev.link.src.port_no)
          self.net.add_edge(ev.link.dst.dpid, ev.link.src.dpid, port=ev.link.dst.port_no)
       elif isinstance(ev, event.EventLinkDelete):
          if (ev.link.src.dpid, ev.link.dst.dpid) in self.net.edges():
             self.logger.info("link %s -> %s, port_no: %s removed", ev.link.src.dpid, ev.link.dst.dpid, ev.link.src.port_no)
             self.net.remove_edge(ev.link.src.dpid, ev.link.dst.dpid)
          if (ev.link.dst.dpid, ev.link.src.dpid) in self.net.edges():
             self.logger.info("link %s -> %s, port_no: %s removed", ev.link.dst.dpid, ev.link.src.dpid, ev.link.dst.port_no)
             self.net.remove_edge(ev.link.dst.dpid, ev.link.src.dpid)
