# Proof-of-concept SDNS server implementation
import base64
from dnslib import AAAA, DNSRecord, DNSError, QTYPE, RR
import json
from socketserver import StreamRequestHandler, ThreadingTCPServer
from socket import AF_INET6
import ssl

SDNS_PORT = 2098

IPV6_GLOBAL_ID = "5f:4934:d08b"
IPV6_SUBNET_ID = "d943"

# Time-to-live given for all lookup requests (in seconds)
DNS_TTL = 12 * 60 * 60

def make_private_ipv6_addr(host_id):
    """
    Builds a string representing a complete private IPv6 address
    :param host_id: string representing the 48-bit host-specific part of the address, e.g. "::1" or "0000:0000:0001"
    :return: IPv6 address string
    """
    # First 16 bytes after subnet ID are always 0, indicating a private address
    return "fd" + IPV6_GLOBAL_ID + ":" + IPV6_SUBNET_ID + "::" + host_id

# Super-simple look-up table of hostname to private IPv6 address
DNS_RECORDS = {
    "xyzmail.sec.mycompany.com.": make_private_ipv6_addr("::1"),
    "private-files.sec.mycompany.com.": make_private_ipv6_addr("::2"),
}


class SDNSRequestHandler(StreamRequestHandler):
    """
    Handles an incoming SDNS lookup request
    """

    def send_json(self, obj):
        """
        Encodes an object as JSON and sends it to the client
        :param obj: object to encode
        :return:
        """
        json_str = json.dumps(obj)
        print("Sending '{}'".format(json_str))
        self.wfile.write(bytes(json_str + "\n", "ascii"))

    def send_error_rsp(self, msg):
        jsondata = {
            "status": 1, # This is where we'd fill in an applicable error code
            "error_message": msg
        }
        self.send_json(jsondata)

    def handle(self):
        request = self.rfile.readline().strip().decode("ascii")
        print("Got request from {}: '{}'".format(self.client_address, request))

        try:
            parsed = json.loads(request)
            dns_query = DNSRecord.parse(base64.b85decode(parsed['query']))
        except json.JSONDecodeError as e:
            print("Error: JSON decode failed", e)
            self.send_error_rsp("Invalid JSON")
            return
        except DNSError as e:
            print("Error: DNS record decode failed", e)
            self.send_error_rsp("Invalid DNS query")
            return

        # Only looking at first question part
        q = dns_query.get_q()
        if q.qtype != QTYPE.AAAA:
            print("Error: Unexpected query type {} (only AAAA/IPv6 lookup supported)".format(q.qtype))
            self.send_error_rsp("Invalid query type")
            return

        # Note: this is a very simplistic implementation that only returns AAAA records
        hostname = q.qname.idna()
        dns_response = dns_query.reply()
        if hostname in DNS_RECORDS:
            priv_addr = DNS_RECORDS[hostname]

            # TODO: generate the virtual IP and install rules into OF switches to map to private addresses to/from
            # virtual ones, then return the assigned virtual IP... just returning the private IP for now

            dns_response.add_answer(RR(rname=hostname, rtype=QTYPE.AAAA, ttl=DNS_TTL, rdata=AAAA(priv_addr)))
        else:
            # Domain not found
            dns_response.header.set_rcode("NXDOMAIN")

        json_resp = {
            "status": 0,
            "response": base64.b85encode(dns_response.pack()).decode("ascii")
        }
        self.send_json(json_resp)


class ThreadingIPv6SSLServer(ThreadingTCPServer):
    address_family = AF_INET6

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=False)
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # TODO: a real implementation would need to verify certificates
        self.ssl_context.load_cert_chain(certfile='test-keys/cert.crt', keyfile='test-keys/key.pem')
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_OPTIONAL
        self.socket = self.ssl_context.wrap_socket(self.socket, server_side=True)

        try:
            self.server_bind()
            self.server_activate()
        except:
            self.server_close()
            raise

if __name__ == "__main__":
    server = ThreadingIPv6SSLServer(("localhost", SDNS_PORT), SDNSRequestHandler)
    print("Listening on port {}...".format(SDNS_PORT))
    server.serve_forever()