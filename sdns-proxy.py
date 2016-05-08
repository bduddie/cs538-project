# Runs on client machines to handle DNS requests, proxying to either the SDNS server (if request is for
# resources on the local network) or a public DNS server (internet services)
import base64
from dnslib import DNSRecord, DNSError
import json
from socketserver import DatagramRequestHandler, ThreadingUDPServer
from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM
import ssl
import threading

from sdns_config import SDNS_HOST, SDNS_PORT

PUBLIC_DNS_ADDR_V4 = "8.8.8.8"
PUBLIC_DNS_ADDR_V6 = "2001:4860:4860::8888"
PUBLIC_DNS_PORT = 53

# The hostname suffix for services hosted on the internal network, e.g. any domain matching *.sec.mycompany.com would
# be an internal secured service that can only be accessed via SDNS
LOCAL_DNS_SUFFIX = ".sec.mycompany.com."


class LocalDNSRequestHandler(DatagramRequestHandler):
    """
    Handles an incoming DNS lookup request. Forwards the request to public DNS or SDNS.
    """

    def proxy_public_dns_query(self):
        req_bin, client_sock = self.request

        # Forward the same request to the public DNS server
        # Use these two lines if your machine supports native IPv6 connectivity to the internet
        #sock = socket(AF_INET6, SOCK_DGRAM)
        #sock.sendto(req_bin, (PUBLIC_DNS_ADDR_V6, PUBLIC_DNS_PORT))
        # Otherwise, use these two for IPv4
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.sendto(req_bin, (PUBLIC_DNS_ADDR_V4, PUBLIC_DNS_PORT))

        resp = sock.recv(4096)
        sock.close()

        # Forward the response to the client
        client_sock.sendto(resp, self.client_address)

    def proxy_sdns_query(self):
        req_bin, client_sock = self.request
        sdns_req = {
            "request_id": 1,
            "query": base64.b85encode(req_bin).decode("ascii"),
            "username": "testuser",
            "auth_token": "testtoken"
        }

        # TODO: using a new connection for each request; this is expensive...
        # TODO: real implementation would require certificate validation
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        with ssl_context.wrap_socket(socket(AF_INET, SOCK_STREAM)) as sdns_sock:
            sdns_sock.connect((SDNS_HOST, SDNS_PORT))
            # Append trailing newline to indicate the end of the request
            payload = bytes(json.dumps(sdns_req) + "\n", "ascii")
            print("Sending SDNS request: '{}'".format(payload))
            sdns_sock.sendall(payload)

            sdns_resp = str(sdns_sock.recv(4096), "ascii")
            print("Got SDNS response:")
            print(str(sdns_resp))

        try:
            parsed = json.loads(sdns_resp)
            if 'status' not in parsed or parsed['status'] != 0 or 'response' not in parsed:
                print("SDNS request failed")
            else:
                client_sock.sendto(base64.b85decode(parsed['response']), self.client_address)
        except json.JSONDecodeError as e:
            print("Error: JSON decode failed", e)

    def handle(self):
        req_bin, client_sock = self.request
        try:
            query = DNSRecord.parse(req_bin)
        except DNSError as e:
            print("Couldn't parse request: ", e)
            return

        print("Got DNS query:")
        print(query)

        # Limitation: only looking at the first query in the request; this seems to be the most common usage
        hostname = query.get_q().qname.idna()
        if hostname.endswith(LOCAL_DNS_SUFFIX):
            self.proxy_sdns_query()
        else:
            self.proxy_public_dns_query()

        print("Done handling request\n")


def send_req_and_print_resp(packet, port):
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.sendto(packet, ("localhost", port))
    resp = sock.recv(2048)

    print("Client got response:")
    try:
        print(DNSRecord.parse(resp))
    except DNSError:
        print(resp)
    sock.close()


def send_test_query_sdns(port):
    req = DNSRecord.question("xyzmail.sec.mycompany.com", qtype="A")

    print("\nIssuing client request (sdns)...")
    send_req_and_print_resp(req.pack(), port)


def send_test_query_public(port):
    # Request the v6 address of google.com
    req = DNSRecord.question("google.com", qtype="A")

    print("Issuing client request (public)...")
    send_req_and_print_resp(req.pack(), port)

if __name__ == "__main__":
    LISTEN_PORT = 1053 # TODO: change to 53 later (requires admin perms)
    server = ThreadingUDPServer(("localhost", LISTEN_PORT), LocalDNSRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print("Server started on port {}".format(LISTEN_PORT))

    # TODO: for testing, send a sample request, then exit... final implementation would just run serve_forever() in the
    # main thread
    send_test_query_sdns(LISTEN_PORT)
    #send_test_query_public(LISTEN_PORT)

    server.shutdown()
    server.server_close()