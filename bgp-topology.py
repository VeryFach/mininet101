#!/usr/bin/env python3

from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
import shutil
import time
from pathlib import Path
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.nodelib import LinuxBridge
import argparse


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")

        # Start FRR daemons
        self.cmd('/usr/lib/frr/zebra -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        self.cmd('/usr/lib/frr/bgpd -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        self.cmd('/usr/lib/frr/ospfd -A 127.0.0.1 -f /etc/frr/frr.conf -d')

        self.cmd('/usr/lib/frr/frr-reload.py --reload /etc/frr/frr.conf')

    def terminate(self):
        self.cmd('killall zebra bgpd ospfd')
        super(LinuxRouter, self).terminate()


class BGPLab(Topo):
    def generate_config(self, router_name, path):
        router = {"name": router_name}
        path = path % router

        template_path = Path("Template/router")
        Path(path).mkdir(exist_ok=True, parents=True)

        for f in template_path.iterdir():
            shutil.copy(f, path)

        self.replace_hostname(path + "/frr.conf", "dummy", router_name)
        self.replace_hostname(path + "/vtysh.conf", "dummy", router_name)

    def replace_hostname(self, filepath, toReplace, replacement):
        with open(filepath) as f:
            content = f.readlines()
        for i in range(len(content)):
            if content[i] == "hostname " + toReplace + "\n":
                content[i] = "hostname " + replacement + "\n"
        with open(filepath, "w") as f:
            f.writelines(content)

    def parse_argument(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-g", "--generateConfig", action="store_true")
        parser.add_argument("-v", "--verbose", action="store_true")
        parser.add_argument("-c", "--config", dest="config_dir", default="config_bgp_lab")
        return parser.parse_args()

    def build(self, *args, **kwargs):
        flags = self.parse_argument()
        if flags.verbose:
            setLogLevel('info')

        config_path = flags.config_dir + "/%(name)s"

        privateDirs = [
            "/var/log",
            ("/etc/frr", config_path),
            "/var/run",
            "/var/mn"
        ]

        # AS 100 Routers
        R11 = self.addNode("R11", cls=LinuxRouter, privateDirs=privateDirs)
        R12 = self.addNode("R12", cls=LinuxRouter, privateDirs=privateDirs)
        R13 = self.addNode("R13", cls=LinuxRouter, privateDirs=privateDirs)
        R14 = self.addNode("R14", cls=LinuxRouter, privateDirs=privateDirs)

        self.addLink(R11, R12)
        self.addLink(R11, R13)
        self.addLink(R12, R14)
        self.addLink(R13, R14)
        self.addLink(R12, R13)

        # AS 200 Routers
        R21 = self.addNode("R21", cls=LinuxRouter, privateDirs=privateDirs)
        R22 = self.addNode("R22", cls=LinuxRouter, privateDirs=privateDirs)
        R23 = self.addNode("R23", cls=LinuxRouter, privateDirs=privateDirs)
        R24 = self.addNode("R24", cls=LinuxRouter, privateDirs=privateDirs)

        self.addLink(R21, R22)
        self.addLink(R21, R23)
        self.addLink(R22, R24)
        self.addLink(R23, R24)
        self.addLink(R22, R23)

        # AS 300 Routers
        R31 = self.addNode("R31", cls=LinuxRouter, privateDirs=privateDirs)
        R32 = self.addNode("R32", cls=LinuxRouter, privateDirs=privateDirs)
        R33 = self.addNode("R33", cls=LinuxRouter, privateDirs=privateDirs)
        R34 = self.addNode("R34", cls=LinuxRouter, privateDirs=privateDirs)

        self.addLink(R31, R32)
        self.addLink(R31, R33)
        self.addLink(R32, R34)
        self.addLink(R33, R34)
        self.addLink(R32, R33)

        self.addLink(R14, R22)
        self.addLink(R23, R34)

        confdir = Path(config_path % {"name": ""})
        if flags.generateConfig or not confdir.exists():
            for n in self.nodes():
                if "R" in n:
                    self.generate_config(n, config_path)

        super().build(*args, **kwargs)


print("=== BGP Topology Mininet ===")
net = Mininet(topo=BGPLab(), switch=LinuxBridge, controller=None)

net.start()
CLI(net)
net.stop()