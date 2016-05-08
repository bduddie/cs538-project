# POX Mixin that handles virtual/private IP address mapping, and drops all traffic to private  addresses that do not
# have a rule installed
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr, IPAddr
import pox.proto.arp_responder as arp
import pox.forwarding.l2_pairs as l2sw

log = core.getLogger()


class SdnsMapper(EventMixin):
    def __init__ (self, arp_table, l2sw_table):
        log.info("Enabling SDNS Module")
        super(SdnsMapper, self).__init__()
        self.arp_table = arp_table
        self.l2sw_table = l2sw_table

        # Stores current list of installed rules; could be used to re-install rules on switches, for debugging, etc.
        self.installed_rules = []

        self.listenTo(core.openflow)

    def _handle_ConnectionUp(self, event):
        msg = of.ofp_flow_mod()

        # Default rule: drop all packets destined for private (protected) IPv4 addresses, as identified by prefix
        msg.match.priority = of.OFP_DEFAULT_PRIORITY + 1
        msg.match.dl_type = 0x0800 # EtherType = IP
        msg.match.nw_dst = "10.250.250.0/24"
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))

        event.connection.send(msg)
        log.info("Default private IP drop rule installed on {}".format(event.dpid))
        log.debug(msg.match.show())

        # Wait until both switches are connected before adding rules
        if len(core.openflow.connections) == 2:
            log.info("Adding virtual:private IP rules in 5 seconds...")
            core.callDelayed(5, self.add_test_rules)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        log.debug("got packet {}".format(packet.dump()))

    def add_test_rules(self):
        """For testing only, install a hard-coded mapping"""
        # C1 non-protected IP 10.0.0.1 connecting to Server's protected IP (10.250.250.4)
        # C1 can connect via virtual IP 10.155.155.4, and Server only sees C1's virtual IP 10.155.155.1
        # Also, setup an ARP responder and Ethernet MAC mapping from FE:EF:<virtual IP addr> to the actual MAC. Note
        # that FE:* has bit 2 of the MSB set to 1, so it is a locally administered MAC.
        log.info("Installing mapping for client1 to protected server")
        self.install_mapping("00:00:00:00:00:01", "10.0.0.1", "FE:EF:10:9B:9B:01", "10.155.155.1",
                             "00:00:00:00:00:04", "10.250.250.4", "FE:EF:10:9B:9B:04", "10.155.155.4")

    @staticmethod
    def send_msg(msg, dpid):
        """Logs & sends an OF message to the given switch"""
        log.debug("Installing rule on switch {}".format(dpid))
        log.debug(msg.show())
        core.openflow.sendToDPID(dpid, msg)

    def install_mapping(self, priv_mac1, priv_ip1, virt_mac1, virt_ip1, priv_mac2, priv_ip2, virt_mac2, virt_ip2, expiry=None):
        self.installed_rules.append(locals())
        log.debug("Installing rule: {}".format(locals()))

        # We have to install 4 rules to handle the mapping. Note that this assumes the two hosts are on different
        # switches; rules would need to be merged to handle the case where both endpoints are on the same switch.
        # In the comments below, "A" is the first address and "B" the second, and ".p" indicates a (true) private
        # address, ".v" a client-specific virtual address, and ".m" a (true) private MAC address. Also "S1" indicates
        # the switch where host A (priv_ip1) is connected, and "S2" for host B.
        msg = of.ofp_flow_mod()
        msg.priority = of.OFP_DEFAULT_PRIORITY + 42
        msg.match.dl_type = 0x0800 # EtherType IPv4

        # S1: if src=A.p and dst=B.v, then set dst=B.p and dl_dst=B.m, forward to the same port that has B.p
        # TODO: for expediency, hard-coding the switch DPIDs here; should really use something like the host_tracker
        # functionality so we can determine this dynamically
        msg.match.nw_src = priv_ip1
        msg.match.nw_dst = virt_ip2
        msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(priv_ip2)))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(priv_mac2)))
        msg.actions.append(of.ofp_action_output(port=self.port_for_mac(1, priv_mac2)))
        SdnsMapper.send_msg(msg, 1)
        msg.actions = []

        # S2: if src=A.p and dst=B.p, then set src=A.v and dl_src=A.v
        msg.match.nw_dst = priv_ip2
        msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(virt_ip1)))
        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(virt_mac1)))
        msg.actions.append(of.ofp_action_output(port=self.port_for_mac(2, priv_mac2)))
        SdnsMapper.send_msg(msg, 2)
        msg.actions = []

        # S2: if src=B.p and dst=A.v, then set dst=A.p
        msg.match.nw_src = priv_ip2
        msg.match.nw_dst = virt_ip1
        msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(priv_ip1)))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(priv_mac1)))
        msg.actions.append(of.ofp_action_output(port=self.port_for_mac(2, priv_mac1)))
        SdnsMapper.send_msg(msg, 2)
        msg.actions = []

        # S1: if src=B.p and dst=A.p, then set src=B.v
        msg.match.nw_dst = priv_ip1
        msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(virt_ip2)))
        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(virt_mac2)))
        msg.actions.append(of.ofp_action_output(port=self.port_for_mac(1, priv_mac1)))
        SdnsMapper.send_msg(msg, 1)

        # Have the switches respond to ARP requests for virtual IPs directly
        timeout = float('inf') if expiry is None else expiry
        self.install_arp_rule(virt_mac1, virt_ip1, timeout)
        self.install_arp_rule(virt_mac2, virt_ip2, timeout)

    def port_for_mac(self, dpid, mac):
        """Inspects the switching table for the given DPID to find the port where we can reach the given MAC"""
        port = self.l2sw_table.get((core.openflow.getConnection(dpid), EthAddr(mac)))
        if port is None:
            log.warn("Don't know where MAC {} is on switch {}; flooding...".format(mac, dpid))
            for (connection, mac), port in self.l2sw_table.items():
                log.warn("  sw {} mac {} port {}".format(connection.dpid, mac, port))
            return of.OFPP_FLOOD
        return port

    def install_arp_rule(self, mac, ip, timeout):
        """Updates the ARP Responder with a new rule"""
        entry = arp.Entry(mac, static=True, flood=False)
        entry.timeout = timeout
        self.arp_table[IPAddr(ip)] = entry


def launch ():
    # Abusing ARPResponder's private ARP table so we can add to it when mappings are added, and we also need to read the
    # Layer 2 switching table to map MAC addresses to ports
    core.registerNew(SdnsMapper, arp._arp_table, l2sw.table)

    # Register the ARP responder module, which we depend on
    arp._learn = False
    arp._eat_packets = True
    responder = core.registerNew(arp.ARPResponder)

    # Override the ARP responder's check for flood method (this is resulting in flooding packets that are already
    # handled by the switching logic, causing errors) -- hot code patching is not a good idea for production use, would
    # want to re-implement this functionality in the correct way for a more robust solution
    responder._check_for_flood = lambda x,y: False

    # Register the base switching logic (l2_pairs)
    core.openflow.addListenerByName("PacketIn", l2sw._handle_PacketIn)

    log.debug("Done launching SDNS mapper and dependencies")
