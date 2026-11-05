"""A DNS query over UDP, for test/dns53/resolved.sh: prints the answer's
rcode and its number of answers. Usage: q.py SERVER NAME [QTYPE]."""
import random
import socket
import struct
import sys


def query(server, name, qtype):
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\0" + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(q, (server, 53))
    r, _ = s.recvfrom(4096)
    if struct.unpack(">H", r[:2])[0] != tid:
        raise SystemExit("an answer to another query")
    rcode = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}.get(r[3] & 0xF, str(r[3] & 0xF))
    return rcode, struct.unpack(">H", r[6:8])[0]


if __name__ == "__main__":
    rcode, answers = query(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 1)
    print(rcode, answers)
