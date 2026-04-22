from scapy.all import conf
print("Available Interfaces:")
for i in conf.ifaces.values():
    ip = getattr(i, "ip", "")
    desc = getattr(i, "description", "")
    name = getattr(i, "name", "")
    print(f"Name: {name} | IP: {ip} | Desc: {desc}")
