#
# Shared definitions for SDNS modules
#

# V4 addressing only expected for simulation; production system should use V6
# This also assumes /24 prefixes
PRIVATE_ADDR_PREFIX_V4 = "10.250.250."
VIRTUAL_ADDR_PREFIX_V4 = "10.155.155."

SDNS_HOST = "10.0.0.3"
SDNS_PORT = 2098