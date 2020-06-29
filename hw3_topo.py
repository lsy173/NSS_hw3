#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange, dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import Controller, RemoteController, Host
from mininet.link import TCLink

class Hw3Topo(Topo):

  def __init__(self, k=1, **opts):
      super(Hw3Topo, self).__init__(**opts)
      switch1 = self.addSwitch('s1', protocols=["OpenFlow13"])
      switch2 = self.addSwitch('s2', protocols=["OpenFlow13"])
      switch3 = self.addSwitch('s3', protocols=["OpenFlow13"])

      # All links between switches need to have 1 Gbps link bandwidth and 1 ms latencies.
      # Use the TCLink option of mininet to impose the performance restrictions on mininet networks.
      self.addLink(switch1, switch2, bw=1000, delay='1ms')
      self.addLink(switch1, switch3, bw=1000, delay='1ms')
      self.addLink(switch2, switch3, bw=1000, delay='1ms')

      host1 = self.addHost('h1', ip='10.0.0.1')
      host2 = self.addHost('h2', ip='10.0.0.2')
      host3 = self.addHost('h3', ip='10.0.0.3')

      self.addLink(host1, switch1, bw=1000, delay='1ms')
      self.addLink(host2, switch2, bw=1000, delay='1ms')
      self.addLink(host3, switch3, bw=1000, delay='1ms')      
   
  def run(self):
      controller = RemoteController('c1', ip='127.0.0.1')
      net = Mininet(topo=self, controller=controller, autoSetMacs=True, link=TCLink)
      net.start()
      dumpNodeConnections(net.hosts)
      dumpNodeConnections(net.switches)
      net.pingAll()
      CLI(net)
      net.stop()

if __name__ == '__main__':
   setLogLevel('info')
   topo = Hw3Topo()
   topo.run()

