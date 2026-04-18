from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr

log = core.getLogger()

class Firewall(object):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        if not packet:
            return

        # 1. MAC Learning
        self.mac_to_port[packet.src] = in_port

        # 2. Firewall Logic
        ip_packet = packet.find('ipv4')
        if ip_packet:
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip

            # Target connection: h1 (10.0.0.1) -> h2 (10.0.0.2)
            if src_ip == IPAddr("10.0.0.1") and dst_ip == IPAddr("10.0.0.2"):
                icmp_packet = packet.find('icmp')
                
                # If it's a Ping Request (Type 8), block it
                if icmp_packet and icmp_packet.type == 8:
                    log.info("FIREWALL: Dropping Ping Request h1 -> h2")
                    self._drop_packet(event)
                    return
                
                # If it's a Ping Reply (Type 0), ALLOW it so h2's ping works
                if icmp_packet and icmp_packet.type == 0:
                    log.info("FIREWALL: Allowing Ping Reply h1 -> h2")
                    pass # Let it fall through to forwarding logic
                
                # Block all other non-ICMP traffic (TCP/UDP) from h1 to h2
                elif not icmp_packet:
                    log.info("FIREWALL: Dropping Generic IP h1 -> h2")
                    self._drop_packet(event)
                    return

        # 3. Learning Switch Forwarding Logic
        if packet.dst in self.mac_to_port:
            out_port = self.mac_to_port[packet.dst]
            self._install_flow(event, out_port)
        else:
            self._flood(event)

    def _drop_packet(self, event):
        """ Installs a drop rule on the switch """
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed)
        msg.idle_timeout = 20
        self.connection.send(msg)

    def _install_flow(self, event, out_port):
        """ Installs a forwarding rule and sends the packet out """
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed)
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

        # Send actual packet
        msg_out = of.ofp_packet_out()
        msg_out.data = event.ofp
        msg_out.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg_out)

    def _flood(self, event):
        """ Floods the packet to all ports """
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info("Smart Firewall Switch Online.")
        Firewall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
