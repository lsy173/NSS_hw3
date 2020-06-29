from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib import hub
from collections import defaultdict
import networkx as nx

DEFAULT_TIMEOUT = 10
SYN_SENT = 'syn-sent'
SYN_RECEIVED = 'syn-received'
ESTABLISHED = 'established'

class StateTable():

  def __init__(self):
      self.protocol = defaultdict(dict)
      self.srcIP = defaultdict(dict)
      self.srcPort = defaultdict(dict)
      self.dstIP = defaultdict(dict)
      self.dstPort = defaultdict(dict)
      self.state = defaultdict(dict)

  def append(self, key, protocol, src_ip, src_port, dst_ip, dst_port, state):
      self.protocol.append(protocol)
      self.srcIP.append(src_ip)
      self.srcPort.append(src_port)
      self.dstIP.append(dst_ip)
      self.dstPort.append(dst_port)
      self.state.append(state)

  def update(self, key, protocol, src_ip, src_port, dst_op, dst_port, state):
      self.protocol[key] = protocol
      self.srcIP[key] = src_ip
      self.srcPort[key] = src_port
      self.dstIP[key] = dst_ip
      self.dstPort[key] = dst_port
      self.state[key] = state

class Firewall(app_manager.RyuApp):

  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


  def __init__(self, *args, **kwargs):
      super(Firewall, self).__init__(*agrs, **kwargs)
      self.net = nx.DiGraph()
      self.hosts_mac_addresses = ['00:00:00:00:00:01', '00:00:00:00:00:02', '00:00:00:00:00:03']
      self.hosts_IP_addresses = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
      self.hosts_mac_ip = {'00:00:00:00:00:01' : "10.0.0.1", '00:00:00:00:00:02' : "10.0.0.2", '00:00:00:00:00:03' : "10.0.0.3"}
      self.hosts_idx = 0
      self.datapath = {}
      self.ARP_table = dict()
      self.switch_mac_table = defaultdict(defaultdict)


  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def swtich_features_handler(self, ev):
      datapath = ev.msg.datapath
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
         mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, idle_timeout=idle_timeout, instructions=instructions)
      else:
         mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=idle_timeout, instructions=instructions)

      datapath.send_msg(mod)


  @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
  def _state_change_handler(self, ev):
      datapath = ev.datapath
      if ev.state == MAIN_DISPATCHER:
         if datapath.id not in self.datapaths:
            self.logger.debug('register datapath: %016x', datapath.id)
            self.datapaths[datapath.id] = datapath
      elif ev.state == DEAD_DISPATCHER:
         if datapath.id in self.datapaths:
            self.logger.debug('unregister datapath: %016x', datapath.id)
            del self.datapaths[datapath.id]


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

  
  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def packet_in_handlerr(self, ev):
      msg = ev.msg
      dp = msg.datapath
      ofp = dp.ofproto
      ofp_parser = dp.ofproto_parser
      in_port = msg.match['in_port']
      buffer_id = msg.buffer_id
      pkt = packet.Packet(msg.data)
      eth = pkt.get_protocol(ethernet.ethernet)
      ipv4 = pkt.get_protocol(ipv4.ipv4)
      tcp = pkt.get_protocol(tcp.tcp)
      udp = pkt.get_protocol(udp.udp)

      mac_dst = eth.dst
      mac_src = eth.src
      dpid = dp.id

      src_ip = ipv4.src
      dst_ip = ipv4.dst

      src_port = tcp.src_port
      dst_port = tcp.dst_port

      if eth.ethertype == ether_types.ETH_TYPE_LLDP:
         # ignore lldp packet
         return

      if mac_src not in self.net:
         self.net.add_node(mac_src)
         self.net.add_edge(dpid, mac_src, port=in_port)
         self.net.add_edge(mac_src, dpid)
