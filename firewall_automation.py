import time
import threading
from collections import defaultdict, deque
import re
from netfilterqueue import NetfilterQueue
import iptc

#CONFIGS
QUEUE_NUM = 2
BLOCK_DURATION = 300
RATE_WINDOW = 10
RATE_THRESHOLD = 20
PAYLOAD_REGEXPS = [re.compile(rb"evil|/etc/passwd", re.IGNORECASE)] 
WHITELIST = []

ip_packet_times = defaultdict(lambda: deque())
blocked_ips = {}
state_lock = threading.Lock()

def add_block_ip(ip):
    with state_lock:
        if ip in blocked_ips:
            return
    table = iptc.Table("filter")
    chain = iptc.Chain(table, "INPUT")
    rule = iptc.Rule()
    rule.src = ip
    rule.target = iptc.Target(rule, "DROP")
    chain.insert_rule(rule)
    with state_lock:
        blocked_ips[ip] = time.time() + BLOCK_DURATION
    print(f"[BLOCK] {ip} blocked for {BLOCK_DURATION} seconds")
    
    
def remove_block_ip(ip):
    table = iptc.Table("filter")
    chain = iptc.Chain(table, "INPUT")
    for rule in chain.rules:
        if rule.src == ip:
            chain.delete_rule(rule)
    with state_lock:
        blocked_ips.pop(ip, None)
    print(f"[UNBLOCK] {ip} removed")
    
    
def cleanup_blocked_ips():
    while True:
        now = time.time()
        with state_lock:
            to_unblock = [ip for ip, until in blocked_ips.items() if until <= now]
        for ip in to_unblock:
            remove_block_ip(ip)
        time.sleep(5)


def check_rate(src_ip):
    now = time.time()
    times = ip_packet_times[src_ip]
    times.append(now)
    while times and times[0] < now - RATE_WINDOW:
        times.popleft()
    if len(times) >= RATE_THRESHOLD:
        return True
    return False

def inspect_payload(payload):
    for rx in PAYLOAD_REGEXPS:
        if rx.search(payload):
            return True
    return False
    
    
def process_packet(pkt):
    data = pkt.get_payload()
    if len(data) < 20:
        pkt.accept()
        return
    src_ip = ".".join(str(b) for b in data[12:16])
    
    if src_ip in WHITELIST:
        pkt.accept()
        return

    with state_lock:
        if src_ip in blocked_ips:
            pkt.drop()
            return

    if check_rate(src_ip) or inspect_payload(data):
        add_block_ip(src_ip)
        pkt.drop()
        return

    pkt.accept()
    
if __name__ == "__main__":
    threading.Thread(target=cleanup_blocked_ips, daemon=True).start()
    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE_NUM, process_packet)
    print(f"Listening on NFQUEUE {QUEUE_NUM}")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()

