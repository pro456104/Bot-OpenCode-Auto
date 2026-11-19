import socket, os, struct, hmac, hashlib, time, base64

LABEL = b"mac1----"


def mac1(pub, msg):
    key = hashlib.blake2s(LABEL + pub, digest_size=16).digest()
    return hmac.new(key, msg, hashlib.blake2s).digest()


pub = base64.b64decode("dsRnvFvkIU88ibWwPaJ86srhLNHfiKUWxFTIpg4IOms=")
print("peer pub len", len(pub))

for host, port in [("169.150.218.36", 51820), ("169.150.218.36", 9999)]:
    for t in (2, 5):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(t)
        pkt = bytearray(struct.pack("<II", 1, 1) + os.urandom(32) + b"\x00" * 48 + b"\x00" * 28)
        pkt += mac1(pub, bytes(pkt[:116])) + b"\x00" * 16
        t0 = time.time()
        try:
            s.sendto(bytes(pkt), (host, port))
            d, a = s.recvfrom(256)
            mtype = struct.unpack("<I", d[:4])[0]
            err = struct.unpack("<I", d[88:92])[0] if len(d) >= 92 else None
            print(f"  {host}:{port} t={t}s -> REPLY {len(d)}B from {a} "
                  f"in {(time.time()-t0)*1000:.0f}ms type={mtype} err={err}")
        except socket.timeout:
            print(f"  {host}:{port} t={t}s -> timeout")
        finally:
            s.close()