import pysnmp

def get_interface_status(host, community, interface):
    # Create a PySNMP session
    session = pysnmp.session(
        transport=pysnmp.TransportUDP(host=host, port=161),
        community=community,
    )

    # Get the interface status
    request = pysnmp.get(
        oid="1.3.6.1.2.1.2.2.1.1",
        target=session,
        variables={"ifIndex": interface},
    )

    # Return the interface status in JSON format
    return request.decode().hex()

if __name__ == "__main__":
    # Get the interface status
    interface_status = get_interface_status("192.168.0.10", "lctura", "fastEthernet1/0")

    # Print the interface status
    print(interface_status)
