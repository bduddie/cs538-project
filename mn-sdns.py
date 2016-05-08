#
# Mininet script for SDNS proof-of-concept
#
from __future__ import print_function

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

from time import sleep

# Enclosing folder for this file, and sdns-server.py/sdns-proxy.py
PROJECT_DIR = '/home/mininet/cs538-project'


class SdnsTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        c1 = self.addHost('c1')
        c2 = self.addHost('c2')
        sdns = self.addHost('sdns')
        server = self.addHost('server')

        left_switch = self.addSwitch( 's1' )
        right_switch = self.addSwitch( 's2' )

        # Add links
        self.addLink(c1, left_switch)
        self.addLink(c2, left_switch)
        self.addLink(left_switch, right_switch)
        self.addLink(right_switch, sdns)
        self.addLink(right_switch, server)


def main():
    net = Mininet(topo=SdnsTopo(), controller=RemoteController, autoSetMacs=True)
    net.start()

    print("Dumping host connections")
    dumpNodeConnections(net.hosts)

    # This is actually required in the current implementation, so that the L2 switch can locate MAC addresses before the
    # virtual IP rules are installed (wouldn't be required in a production system)
    print("Testing network connectivity")
    net.pingAll()

    # Replace the server's default IP address (10.0.0.4) with a private/protected one (10.250.250.4)
    server = net.get('server')
    server.setIP("10.250.250.4")

    print("Starting SDNS server...")
    sdns = net.get('sdns')
    sdns.cmd("python3 {}/sdns-server.py&".format(PROJECT_DIR))
    sdns_pid = int(sdns.cmd("echo $!"))

    # Wait for POX to install virtual IP rules (normally this would be triggered via SDNS client query, but we're
    # hard-coding the expected result for now)
    print("Waiting for rules to be installed...")
    sleep(10)

    print("Running SDNS proxy test")
    c1 = net.get('c1')
    result = c1.cmd("python3 {}/sdns-proxy.py".format(PROJECT_DIR))
    print("Result: {}".format(result))

    print("\n*** Start ping tests ***\n")
    print("Attempting to ping protected server's virtual IP from c1 (should succeed)")
    result = c1.cmd("ping -c 1 10.155.155.4 2>&1")
    print(result)

    print("Attempting to ping protected server's private IP from c1 (should fail)")
    result = c1.cmd("ping -c 1 10.250.250.4 2>&1")
    print(result)

    print("Attempting to ping protected server's virtual IP from c2 (should fail)")
    c2 = net.get('c2')
    result = c2.cmd("ping -c 1 10.155.155.4 2>&1")
    print(result)

    print("Attempting to ping c1's virtual IP from sever (should succeed)")
    result = server.cmd("ping -c 1 10.155.155.1 2>&1")
    print(result)
    print("\n*** End ping tests ***\n")

    print("Stopping SDNS server (PID {})".format(sdns_pid))
    sdns.cmd("kill {}".format(sdns_pid))
    print("Stopping mininet")
    net.stop()

topos = {'sdns': (lambda: SdnsTopo())}
if __name__ == '__main__':
    setLogLevel('info')
    main()
