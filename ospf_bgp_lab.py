#!/usr/bin/env python3
from mininet.node import Node
from mininet.log import setLogLevel
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.nodelib import LinuxBridge
import shutil
import time
from pathlib import Path
import argparse

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        self.cmd('/usr/lib/frr/zebra -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        self.cmd('/usr/lib/frr/bgpd -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        self.cmd('/usr/lib/frr/ospfd -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        self.cmd('/usr/lib/frr/frr-reload.py --reload /etc/frr/frr.conf')

    def terminate(self):
        self.cmd('killall zebra bgpd ospfd 2>/dev/null || true')
        super(LinuxRouter, self).terminate()


class OSPFBGPLab(Topo):
    def parse_argument(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-g", "--generateConfig", action="store_true",
                            help="Generate router config files from template.")
        parser.add_argument("-v", "--verbose", action="store_true",
                            help="Verbose output.")
        parser.add_argument("-c", "--config", dest="config_dir",
                            default="config_bgp_lab",
                            help="Directory to save router configs.")
        parser.add_argument("--scenario", choices=["1", "2"], default="1",
                            help="Scenario (1=LocalPref/AS-Path Prepend, 2=Prefix Filtering).")
        return parser.parse_args()

    def generate_config(self, router_name, path, asn_map, neighbor_map, advertised_prefixes, scenario):
        """Generate frr.conf based on template with dynamic replacement."""
        template_dir = Path("Template/router")
        path = Path(path % {"name": router_name})
        path.mkdir(parents=True, exist_ok=True)

        for file in template_dir.iterdir():
            shutil.copy(file, path)

        frr_conf = path / "frr.conf"
        if not frr_conf.exists():
            print(f"Warning: Template missing frr.conf in {template_dir}")
            return

        base = router_name.split("_")[0]
        asn = asn_map.get(base, 65000)
        neighbors = neighbor_map.get(base, [])
        prefixes = advertised_prefixes.get(asn, [])

        content = frr_conf.read_text()

        content = content.replace("hostname dummy", f"hostname {router_name}")

        content = content.replace("!ASN", f"router bgp {asn}\n bgp router-id 1.1.1.{asn % 100}")

        neighbor_lines = []
        for ip, nas in neighbors:
            if scenario == "1":
                neighbor_lines.append(
                    f" neighbor {ip} remote-as {nas}\n"
                    f" neighbor {ip} route-map IMPORT-LP-IN in\n"
                    f" neighbor {ip} route-map EXPORT-PREP out"
                )
            else:
                neighbor_lines.append(
                    f" neighbor {ip} remote-as {nas}\n"
                    f" neighbor {ip} route-map IMPORT-PFX-FILTER in\n"
                    f" neighbor {ip} route-map EXPORT-PFX-FILTER out"
                )
        content = content.replace("!NEIGHBORS", "\n".join(neighbor_lines) or "! no neighbors")

        network_lines = [f" network {p}" for p in prefixes]
        content = content.replace("!NETWORKS", "\n".join(network_lines) or "! no networks")

        if scenario == "1":
            policy = """
ip prefix-list ALLOW-ALL seq 5 permit 0.0.0.0/0 le 32
!
route-map IMPORT-LP-IN permit 10
 match ip address prefix-list ALLOW-ALL
 set local-preference 200
!
route-map EXPORT-PREP permit 10
 set as-path prepend {asn} {asn}
!
""".format(asn=asn)
        else:
            policy = """
ip prefix-list ACCEPT_ONLY_23 seq 10 permit 10.0.0.0/8 le 23
!
route-map IMPORT-PFX-FILTER permit 10
 match ip address prefix-list ACCEPT_ONLY_23
!
route-map IMPORT-PFX-FILTER deny 20
!
route-map EXPORT-PFX-FILTER permit 10
 match ip address prefix-list OWN_PREFIXES
!
""" + "\n".join(f"ip prefix-list OWN_PREFIXES permit {p}" for p in prefixes) + "\n!"
        content = content.replace("!POLICY", policy)

        frr_conf.write_text(content)
        print(f"Generated config for {router_name} (ASN {asn}) in {path}")

    def build(self, *args, **kwargs):
        flags = self.parse_argument()
        if flags.verbose:
            setLogLevel('info')

        config_path = flags.config_dir + "/%(name)s"
        privateDirs = [
            ('/var/log', '/var/log'),
            ('/etc/frr', config_path),
            ('/var/run', '/var/run'),
            ('/var/mn', '/var/mn')
        ]

        asn_map = {"R1": 100, "R2": 200, "R3": 300}
        advertised_prefixes = {
            100: ["10.100.0.0/23", "10.100.2.0/24"],
            200: ["10.200.0.0/23", "10.200.2.0/24"],
            300: ["10.300.0.0/23", "10.300.2.0/24"]
        }
        neighbor_map = {
            "R1": [("10.0.12.2", 200), ("10.0.13.2", 300)],
            "R2": [("10.0.12.1", 100), ("10.0.23.2", 300)],
            "R3": [("10.0.13.1", 100), ("10.0.23.1", 200)]
        }

        scenario = flags.scenario

        # Client di AS100
        C1_1 = self.addHost('C1_1', ip="172.16.1.2/24", defaultRoute="via 172.16.1.1")
        C1_2 = self.addHost('C1_2', ip="172.16.2.2/24", defaultRoute="via 172.16.2.1")
        R1 = self.addNode("R1", cls=LinuxRouter, ip=None, privateDirs=privateDirs, inNamespace=True)
        S1 = self.addSwitch("S1", inNamespace=True)
        R1_1 = self.addNode("R1_1", cls=LinuxRouter, ip=None, privateDirs=privateDirs, inNamespace=True)
        R1_2 = self.addNode("R1_2", cls=LinuxRouter, ip=None, privateDirs=privateDirs, inNamespace=True)

        self.addLink(S1, R1, intfName2="eth0")
        self.addLink(S1, R1_1, intfName2="eth0")
        self.addLink(S1, R1_2, intfName2="eth0")
        self.addLink(C1_1, R1_1, intfName2="eth1", params2={'ip': '172.16.1.1/24'})
        self.addLink(C1_2, R1_2, intfName2="eth1", params2={'ip': '172.16.2.1/24'})

        # Client di AS200
        C2_1 = self.addHost('C2_1', ip="172.17.1.2/24", defaultRoute="via 172.17.1.1")
        C2_2 = self.addHost('C2_2', ip="172.17.2.2/24", defaultRoute="via 172.17.2.1")
        R2 = self.addNode("R2", cls=LinuxRouter, ip=None, privateDirs=privateDirs, inNamespace=True)
        S2 = self.addSwitch("S2", inNamespace=True)
        R2_1 = self.addNode("R2_1", cls=LinuxRouter, ip=None, privateDirs=privateDirs, inNamespace=True)
        R2_2 = self.addNode("R2_2", cls=LinuxRouter, ip=None, privateDirs=privateDirs, inNamespace=True)
        self.addLink(S2, R2, intfName2="eth0")
        self.addLink(S2, R2_1, intfName2="eth0")
        self.addLink(S2, R2_2, intfName2="eth0")
        self.addLink(C2_1, R2_1, intfName2="eth1", params2={'ip': '172.17.1.1/24'})
        self.addLink(C2_2, R2_2, intfName2="eth1", params2={'ip': '172.17.2.1/24'})

        # Client di AS300
        C3_1 = self.addHost('C3_1', ip="172.18.1.2/24", defaultRoute="via 172.18.1.1")
        C3_2 = self.addHost('C3_2', ip="172.18.2.2/24", defaultRoute="via 172.18.2.1")
        R3 = self.addNode("R3", cls=LinuxRouter, ip=None, privateDirs=privateDirs, inNamespace=True)
        S3 = self.addSwitch("S3", inNamespace=True)
        R3_1 = self.addNode("R3_1", cls=LinuxRouter, ip=None, privateDirs=privateDirs, inNamespace=True)
        R3_2 = self.addNode("R3_2", cls=LinuxRouter, ip=None, privateDirs=privateDirs, inNamespace=True)
        self.addLink(S3, R3, intfName2="eth0")
        self.addLink(S3, R3_1, intfName2="eth0")
        self.addLink(S3, R3_2, intfName2="eth0")
        self.addLink(C3_1, R3_1, intfName2="eth1", params2={'ip': '172.18.1.1/24'})
        self.addLink(C3_2, R3_2, intfName2="eth1", params2={'ip': '172.18.2.1/24'})

        # Backbone antar AS
        self.addLink(R1, R2, intfName1="eth1", intfName2="eth1",
                     params1={'ip': '10.0.12.1/30'}, params2={'ip': '10.0.12.2/30'})
        self.addLink(R1, R3, intfName1="eth2", intfName2="eth1",
                     params1={'ip': '10.0.13.1/30'}, params2={'ip': '10.0.13.2/30'})
        self.addLink(R2, R3, intfName1="eth2", intfName2="eth2",
                     params1={'ip': '10.0.23.1/30'}, params2={'ip': '10.0.23.2/30'})

        if flags.generateConfig:
            for n in self.nodes():
                info = self.nodeInfo(n)
                if "cls" in info and info["cls"].__name__ == "LinuxRouter":
                    self.generate_config(n, config_path, asn_map, neighbor_map, advertised_prefixes, scenario)

        super().build(*args, **kwargs)


if __name__ == "__main__":
    print("=== OSPF + BGP Lab (Template-Based Config) ===")
    topo = OSPFBGPLab()
    start = time.time()
    net = Mininet(topo=topo, switch=LinuxBridge, controller=None, autoSetMacs=True)
    end = time.time()
    print(f"Topology built in {end - start:.2f} seconds")

    try:
        net.start()
        CLI(net)
    finally:
        net.stop()
