from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from subprocess import call
import shutil
import time
from pathlib import Path
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
import argparse


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        self.cmd('/usr/lib/frr/zebra -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        # start ospfd if present in config
        self.cmd('/usr/lib/frr/ospfd -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        # start bgpd if configured (zebra/bgpd will check conf)
        self.cmd('/usr/lib/frr/bgpd -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        # reload to ensure zebra picks up interface statements in frr.conf
        self.cmd('/usr/lib/frr/frr-reload.py  --reload /etc/frr/frr.conf')

    def terminate(self):
        self.cmd('killall zebra staticd ospfd ospf6d bgpd pimd pim6d isisd vrrpd')
        super(LinuxRouter, self).terminate()


class OSPFBGPLab(Topo):
    def parse_argument(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-g', '--generateConfig', action='store_true',
                            help='Generate router config files (overwrites existing)')
        parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
        parser.add_argument('-c', '--config', dest='config_dir', default='config_ospf_lab',
                            help='Directory to write router configs (default: ./config_ospf_lab)')
        parser.add_argument('-s', '--scenario', choices=['1', '2'], default='1',
                            help='Experiment scenario: 1 (localpref+prepend) or 2 (prefix filtering)')
        return parser.parse_args()

    def generate_config(self, router_name, path, scenario, router_defs):
        """Write frr.conf for a given router based on router_defs and scenario."""
        Path(path).mkdir(parents=True, exist_ok=True)
        cfgfile = Path(path) / 'frr.conf'
        r = router_defs[router_name]

        # build interface stanza (zebra can configure addresses if declared here)
        interfaces = ''
        for ifn, ip in r.get('interfaces', {}).items():
            interfaces += f"interface {ifn}\n ip address {ip}\n exit\n"

        # ospf networks (intra-as)
        ospf = f"router ospf\n ospf router-id {r['router_id']}\n"
        for net in r.get('ospf_networks', []):
            ospf += f" network {net} area 0\n"

        # bgp stanza (only for border routers)
        bgp = ''
        if 'asn' in r:
            bgp = f"router bgp {r['asn']}\n bgp router-id {r['router_id']}\n bgp log-neighbor-changes\n"
            bgp += " address-family ipv4 unicast\n"
            # advertise networks
            for net in r.get('networks', []):
                bgp += f"  network {net}\n"
            # neighbors
            for nbr in r.get('bgp_neighbors', []):
                bgp += f"  neighbor {nbr['ip']} remote-as {nbr['remote_as']}\n"
                # attach route-maps depending on scenario
                if scenario == '1':
                    if nbr.get('in_route_map'):
                        bgp += f"  neighbor {nbr['ip']} route-map {nbr['in_route_map']} in\n"
                    if nbr.get('out_route_map'):
                        bgp += f"  neighbor {nbr['ip']} route-map {nbr['out_route_map']} out\n"
                else:
                    # scenario 2 uses prefix-list based export
                    if nbr.get('out_route_map'):
                        bgp += f"  neighbor {nbr['ip']} route-map {nbr['out_route_map']} out\n"
                    if nbr.get('in_route_map'):
                        bgp += f"  neighbor {nbr['ip']} route-map {nbr['in_route_map']} in\n"
            bgp += " exit-address-family\n"

        # build policy definitions based on scenario
        policies = ''
        if scenario == '1':
            # Import policy: set local-preference for routes from certain AS (example: prefer AS200)
            policies += "route-map LP-IN permit 10\n set local-preference 200\n"
            # Export policy: AS-path prepend
            policies += "route-map PREPEND-OUT permit 10\n set as-path prepend {asn} {asn} {asn}\n".format(asn=r.get('asn', r.get('asn', 0)))
        else:
            # scenario 2: accept only /23 on import; export only own prefixes (/23 and /24)
            # create prefix-lists
            # accept /23 only
            if r.get('is_border'):
                policies += f"ip prefix-list ACCEPT-23 seq 5 permit {r.get('summary','0.0.0.0/0')} ge 23 le 23\n"
            # export-only route-map (match own prefixes)
            policies += "route-map EXPORT-ONLY permit 10\n"
            policies += " match ip address prefix-list OWN-PREFIXES\n"
            # define OWN-PREFIXES for router networks
            for i, net in enumerate(r.get('networks', []), start=5):
                policies += f"ip prefix-list OWN-PREFIXES seq {i} permit {net}\n"

        # compose final file
        content = f"hostname {router_name}\nlog file /var/log/frr/{router_name}.log\nservice integrated-vtysh-config\n\n"
        content += interfaces + '\n' + ospf + '\n' + bgp + '\n' + policies
        content += '\nline vty\n'

        cfgfile.write_text(content)
        print(f'Wrote {cfgfile}')

    def build(self, *args, **kwargs):
        flags = self.parse_argument()
        if flags.verbose:
            setLogLevel('info')

        config_path = flags.config_dir + '/%(name)s'

        # Define routers and their AS, interfaces, and networks
        # We'll use names R1,R1_1,R1_2,R2,...
        router_defs = {
            'R1':{
                'asn':100,
                'router_id':'1.1.1.1',
                'is_border':True,
                'interfaces':{'eth0':'172.16.1.1/24','eth1':'10.0.12.1/30','eth2':'10.0.13.1/30'},
                'ospf_networks':['172.16.0.0/16','10.0.12.0/30','10.0.13.0/30'],
                'networks':['172.16.0.0/23','172.16.2.0/24'],
                'bgp_neighbors':[{'ip':'10.0.12.2','remote_as':200,'in_route_map':'LP-IN','out_route_map':'PREPEND-OUT'},{'ip':'10.0.13.2','remote_as':300,'in_route_map':'LP-IN','out_route_map':'PREPEND-OUT'}],
                'summary':'172.16.0.0/23'
            },
            'R2':{
                'asn':200,
                'router_id':'2.2.2.2',
                'is_border':True,
                'interfaces':{'eth0':'172.17.1.1/24','eth1':'10.0.12.2/30','eth2':'10.0.23.1/30'},
                'ospf_networks':['172.17.0.0/16','10.0.12.0/30','10.0.23.0/30'],
                'networks':['172.17.0.0/23','172.17.2.0/24'],
                'bgp_neighbors':[{'ip':'10.0.12.1','remote_as':100,'in_route_map':None,'out_route_map':None},{'ip':'10.0.23.2','remote_as':300,'in_route_map':None,'out_route_map':None}],
                'summary':'172.17.0.0/23'
            },
            'R3':{
                'asn':300,
                'router_id':'3.3.3.3',
                'is_border':True,
                'interfaces':{'eth0':'172.18.1.1/24','eth1':'10.0.13.2/30','eth2':'10.0.23.2/30'},
                'ospf_networks':['172.18.0.0/16','10.0.13.0/30','10.0.23.0/30'],
                'networks':['172.18.0.0/23','172.18.2.0/24'],
                'bgp_neighbors':[{'ip':'10.0.13.1','remote_as':100,'in_route_map':None,'out_route_map':'EXPORT-ONLY'},{'ip':'10.0.23.1','remote_as':200,'in_route_map':None,'out_route_map':'EXPORT-ONLY'}],
                'summary':'172.18.0.0/23'
            }
        }

        # internal routers (only ospf)
        def internal_def(name, base_net_prefix, idx):
            return {
                'router_id':f'10.0.{idx}.{idx}',
                'interfaces':{'eth0':f'{base_net_prefix}.{1}/24'},
                'ospf_networks':[f'{base_net_prefix}.0/24']
            }

        # Start building topology (nodes and links)
        # hosts in AS100
        C1_1 = self.addHost('C1_1', ip='172.16.1.2/24', defaultRoute='via 172.16.1.1')
        C1_2 = self.addHost('C1_2', ip='172.16.2.2/24', defaultRoute='via 172.16.2.1')
        R1 = self.addNode('R1', cls=LinuxRouter, ip=None, inNamespace=True)
        S1 = self.addSwitch('S1', inNamespace=True)
        R1_1 = self.addNode('R1_1', cls=LinuxRouter, ip=None, inNamespace=True)
        R1_2 = self.addNode('R1_2', cls=LinuxRouter, ip=None, inNamespace=True)
        self.addLink(S1, R1, intfName2='eth0')
        self.addLink(S1, R1_1, intfName2='eth0')
        self.addLink(S1, R1_2, intfName2='eth0')
        self.addLink(C1_1, R1_1, intfName2='eth1')
        self.addLink(C1_2, R1_2, intfName2='eth1')

        # AS200
        C2_1 = self.addHost('C2_1', ip='172.17.1.2/24', defaultRoute='via 172.17.1.1')
        C2_2 = self.addHost('C2_2', ip='172.17.2.2/24', defaultRoute='via 172.17.2.1')
        R2 = self.addNode('R2', cls=LinuxRouter, ip=None, inNamespace=True)
        S2 = self.addSwitch('S2', inNamespace=True)
        R2_1 = self.addNode('R2_1', cls=LinuxRouter, ip=None, inNamespace=True)
        R2_2 = self.addNode('R2_2', cls=LinuxRouter, ip=None, inNamespace=True)
        self.addLink(S2, R2, intfName2='eth0')
        self.addLink(S2, R2_1, intfName2='eth0')
        self.addLink(S2, R2_2, intfName2='eth0')
        self.addLink(C2_1, R2_1, intfName2='eth1')
        self.addLink(C2_2, R2_2, intfName2='eth1')

        # AS300
        C3_1 = self.addHost('C3_1', ip='172.18.1.2/24', defaultRoute='via 172.18.1.1')
        C3_2 = self.addHost('C3_2', ip='172.18.2.2/24', defaultRoute='via 172.18.2.1')
        R3 = self.addNode('R3', cls=LinuxRouter, ip=None, inNamespace=True)
        S3 = self.addSwitch('S3', inNamespace=True)
        R3_1 = self.addNode('R3_1', cls=LinuxRouter, ip=None, inNamespace=True)
        R3_2 = self.addNode('R3_2', cls=LinuxRouter, ip=None, inNamespace=True)
        self.addLink(S3, R3, intfName2='eth0')
        self.addLink(S3, R3_1, intfName2='eth0')
        self.addLink(S3, R3_2, intfName2='eth0')
        self.addLink(C3_1, R3_1, intfName2='eth1')
        self.addLink(C3_2, R3_2, intfName2='eth1')

        # backbone links between R1,R2,R3 for BGP (no switches)
        self.addLink(R1, R2, intfName1='eth1', intfName2='eth1')
        self.addLink(R1, R3, intfName1='eth2', intfName2='eth1')
        self.addLink(R2, R3, intfName1='eth2', intfName2='eth2')

        # if config generation requested, create per-router config directories and conf files
        if flags.generateConfig:
            for n in self.nodes():
                node_info = self.nodeInfo(n)
                if 'cls' in node_info and node_info['cls'].__name__ == 'LinuxRouter':
                    # determine config path
                    path = (flags.config_dir + '/%s') % n
                    # choose router_def if exists else generate a minimal internal one
                    if n in router_defs:
                        self.generate_config(n, path, flags.scenario, router_defs)
                    else:
                        # internal routers get a small ospf-only config
                        intr = {'router_id': '10.10.10.10', 'interfaces': {'eth0': '0.0.0.0/24'}, 'ospf_networks': []}
                        router_defs[n] = intr
                        self.generate_config(n, path, flags.scenario, router_defs)

        # call super to finish building mininet topology
        super().build(*args, **kwargs)


if __name__ == '__main__':
    topo = OSPFBGPLab()
    print('Initializing Mininet topology for OSPF+BGP lab')
    net = Mininet(topo=topo, link=TCLink, controller=None)
    try:
        net.start()
        print('Network started. Use mininet CLI to interact.')
        CLI(net)
    finally:
        net.stop()
        print('Network stopped.')