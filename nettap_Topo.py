#!usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange, dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import Controller, RemoteController, Host

class NettapTopo(Topo):

   def __init__(self, k=1, **opts):
       super(NettapTopo, self).__init__(**opts)
       switch1 = self.addSwitch('s1', protocols=["OpenFlow13"])
       switch2 = self.addSwitch('s2', protocols=["OpenFlow13"])
       switch3 = self.addSwitch('s3', protocols=["OpenFlow13"])
 
       self.addLink(switch1, switch2)
       self.addLink(switch1, switch3)
       
       tap_host = self.addHost('h1')
       host1 = self.addHost('h2')
       host2 = self.addHost('h3')
       host3 = self.addHost('h4')

       self.addLink(switch2, tap_host)
       self.addLink(switch2, host1)
       self.addLink(switch3, host2)
       self.addLink(switch3, host3)

   def run(self):
       controller = RemoteController('c1', ip='127.0.0.1')
       net = Mininet(topo=self, controller=controller, autoSetMacs=True)
       net.start()
       dumpNodeConnections(net.hosts)
       dumpNodeConnections(net.switches)
       net.pingAll()
       CLI(net)
       net.stop()

if __name__ == '__main__':
   setLogLevel('info')
   topo = NettapTopo()
   topo.run()
