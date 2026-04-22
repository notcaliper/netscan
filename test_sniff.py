from scapy.all import sniff, conf
def _cb(p):
    print("Packet!", len(p))
print("Sniffing...")
try:
    sniff(iface="Wi-Fi", count=5, prn=_cb, store=False, L2socket=conf.L3socket)
except Exception as e:
    print("L3 fail:", e)
