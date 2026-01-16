"""
Network Mapper - IoT Network Topology and Relationship Mapping
Device relationship mapping, network topology visualization, gateway identification
"""

import json
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict, field
from collections import defaultdict
import ipaddress
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class NetworkDevice:
    """Network device information"""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    role: Optional[str] = None  # gateway, host, server, etc.
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    connections: List[str] = field(default_factory=list)  # Connected IPs
    traffic_stats: Optional[Dict] = None
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class NetworkSegment:
    """Network segment/subnet"""
    subnet: str
    network_id: str
    gateway: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    devices: List[NetworkDevice] = field(default_factory=list)
    vlan_id: Optional[int] = None
    description: Optional[str] = None
    security_zone: Optional[str] = None  # DMZ, internal, external


@dataclass
class NetworkTopology:
    """Complete network topology"""
    topology_id: str
    name: str
    segments: List[NetworkSegment] = field(default_factory=list)
    device_graph: Dict[str, List[str]] = field(default_factory=dict)  # Adjacency list
    gateway_devices: List[str] = field(default_factory=list)
    total_devices: int = 0
    mapped_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class NetworkMapper:
    """
    Network Topology Mapper
    Map and analyze IoT network infrastructure
    """

    def __init__(self):
        """Initialize network mapper"""
        self.devices: Dict[str, NetworkDevice] = {}
        self.segments: Dict[str, NetworkSegment] = {}
        self.topology: Optional[NetworkTopology] = None

        # Device role detection patterns
        self.role_patterns = {
            'gateway': {
                'keywords': ['router', 'gateway', 'firewall'],
                'ports': [23, 22, 80, 443],
                'characteristics': ['multiple_interfaces', 'routing_capable'],
            },
            'server': {
                'keywords': ['server', 'nas', 'storage'],
                'ports': [80, 443, 21, 22, 445, 3389],
                'characteristics': ['many_services'],
            },
            'webcam': {
                'keywords': ['camera', 'webcam', 'ipcam'],
                'ports': [80, 554, 8000],
                'characteristics': ['rtsp_service'],
            },
            'host': {
                'keywords': ['workstation', 'pc', 'laptop'],
                'ports': [135, 139, 445],
                'characteristics': ['client_services'],
            },
        }

    def add_device(
        self,
        ip: str,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        device_type: Optional[str] = None,
        vendor: Optional[str] = None,
        open_ports: Optional[List[int]] = None,
        services: Optional[Dict[int, str]] = None
    ) -> NetworkDevice:
        """
        Add device to network map

        Args:
            ip: Device IP address
            mac: MAC address
            hostname: Hostname
            device_type: Device type
            vendor: Vendor name
            open_ports: List of open ports
            services: Service mapping

        Returns:
            Network device
        """
        if ip in self.devices:
            device = self.devices[ip]
            device.last_seen = datetime.utcnow().isoformat()
        else:
            device = NetworkDevice(
                ip=ip,
                mac=mac,
                hostname=hostname,
                device_type=device_type,
                vendor=vendor,
                open_ports=open_ports or [],
                services=services or {},
            )

            # Detect device role
            device.role = self._detect_device_role(device)

            self.devices[ip] = device

            # Add to appropriate segment
            self._assign_to_segment(device)

        logger.info(f"Added device: {ip} (role: {device.role})")
        return device

    def add_connection(self, src_ip: str, dst_ip: str):
        """
        Add connection between devices

        Args:
            src_ip: Source IP
            dst_ip: Destination IP
        """
        if src_ip in self.devices:
            if dst_ip not in self.devices[src_ip].connections:
                self.devices[src_ip].connections.append(dst_ip)

        if dst_ip in self.devices:
            if src_ip not in self.devices[dst_ip].connections:
                self.devices[dst_ip].connections.append(src_ip)

    def map_network(
        self,
        ip_range: Optional[str] = None,
        devices: Optional[List[Dict]] = None
    ) -> NetworkTopology:
        """
        Map network topology

        Args:
            ip_range: IP range to map (CIDR notation)
            devices: Pre-discovered devices to map

        Returns:
            Network topology
        """
        logger.info(f"Mapping network topology")

        if devices:
            # Add provided devices
            for device_info in devices:
                self.add_device(**device_info)

        if ip_range:
            # Discover devices in range (simulated)
            self._discover_range(ip_range)

        # Build topology
        topology = self._build_topology()

        self.topology = topology
        logger.info(f"Network topology mapped: {topology.total_devices} devices, {len(topology.segments)} segments")

        return topology

    def identify_gateways(self) -> List[NetworkDevice]:
        """
        Identify gateway devices in network

        Returns:
            List of gateway devices
        """
        logger.info("Identifying gateway devices")

        gateways = []

        for device in self.devices.values():
            # Check if device is a gateway
            is_gateway = False

            # Role-based identification
            if device.role == 'gateway':
                is_gateway = True

            # Port-based identification
            gateway_ports = [23, 22, 80, 443]
            if any(port in device.open_ports for port in gateway_ports):
                if device.device_type in ['router', 'firewall', 'gateway']:
                    is_gateway = True

            # Connectivity-based identification (many connections)
            if len(device.connections) > 5:
                is_gateway = True

            # Check if it's a network gateway IP (usually .1 or .254)
            try:
                ip_obj = ipaddress.ip_address(device.ip)
                if device.ip.endswith('.1') or device.ip.endswith('.254'):
                    is_gateway = True
            except:
                pass

            if is_gateway:
                device.role = 'gateway'
                gateways.append(device)

        logger.info(f"Identified {len(gateways)} gateway devices")
        return gateways

    def analyze_subnet(self, subnet: str) -> Dict[str, Any]:
        """
        Analyze a network subnet

        Args:
            subnet: Subnet in CIDR notation

        Returns:
            Subnet analysis
        """
        logger.info(f"Analyzing subnet: {subnet}")

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except:
            logger.error(f"Invalid subnet: {subnet}")
            return {}

        # Find devices in subnet
        subnet_devices = []
        for device in self.devices.values():
            try:
                if ipaddress.ip_address(device.ip) in network:
                    subnet_devices.append(device)
            except:
                continue

        # Analyze
        analysis = {
            'subnet': subnet,
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'num_addresses': network.num_addresses,
            'total_devices': len(subnet_devices),
            'device_types': self._count_device_types(subnet_devices),
            'device_roles': self._count_device_roles(subnet_devices),
            'gateway': self._find_subnet_gateway(subnet_devices),
            'utilization': len(subnet_devices) / (network.num_addresses - 2) * 100 if network.num_addresses > 2 else 0,
        }

        return analysis

    def get_device_neighbors(self, ip: str, depth: int = 1) -> Dict[str, List[str]]:
        """
        Get neighboring devices

        Args:
            ip: Device IP
            depth: Search depth (number of hops)

        Returns:
            Dictionary of neighbors by depth
        """
        if ip not in self.devices:
            return {}

        neighbors: Dict[str, List[str]] = {f'depth_{i}': [] for i in range(1, depth + 1)}
        visited = {ip}
        current_level = [ip]

        for level in range(1, depth + 1):
            next_level = []

            for device_ip in current_level:
                if device_ip in self.devices:
                    for connected_ip in self.devices[device_ip].connections:
                        if connected_ip not in visited:
                            neighbors[f'depth_{level}'].append(connected_ip)
                            visited.add(connected_ip)
                            next_level.append(connected_ip)

            current_level = next_level

        return neighbors

    def generate_device_graph(self) -> Dict[str, List[str]]:
        """
        Generate device connectivity graph

        Returns:
            Adjacency list representation
        """
        graph = {}

        for ip, device in self.devices.items():
            graph[ip] = device.connections.copy()

        return graph

    def find_critical_devices(self) -> List[NetworkDevice]:
        """
        Find critical devices (high connectivity, gateways, etc.)

        Returns:
            List of critical devices
        """
        critical = []

        for device in self.devices.values():
            is_critical = False

            # Gateway devices are critical
            if device.role == 'gateway':
                is_critical = True

            # High connectivity
            if len(device.connections) >= 10:
                is_critical = True

            # Many services
            if len(device.services) >= 5:
                is_critical = True

            if is_critical:
                critical.append(device)

        # Sort by number of connections
        critical.sort(key=lambda d: len(d.connections), reverse=True)

        logger.info(f"Found {len(critical)} critical devices")
        return critical

    def _detect_device_role(self, device: NetworkDevice) -> str:
        """Detect device role from characteristics"""

        for role, patterns in self.role_patterns.items():
            score = 0

            # Check keywords in hostname
            if device.hostname:
                hostname_lower = device.hostname.lower()
                for keyword in patterns['keywords']:
                    if keyword in hostname_lower:
                        score += 2

            # Check device type
            if device.device_type:
                device_type_lower = device.device_type.lower()
                for keyword in patterns['keywords']:
                    if keyword in device_type_lower:
                        score += 3

            # Check ports
            matching_ports = sum(1 for port in device.open_ports if port in patterns['ports'])
            score += matching_ports

            if score >= 3:
                return role

        return 'host'  # Default role

    def _assign_to_segment(self, device: NetworkDevice):
        """Assign device to network segment"""
        try:
            ip_obj = ipaddress.ip_address(device.ip)
            # Assume /24 subnet
            subnet = str(ipaddress.ip_network(f"{device.ip}/24", strict=False))

            if subnet not in self.segments:
                segment = NetworkSegment(
                    subnet=subnet,
                    network_id=hashlib.md5(subnet.encode()).hexdigest()[:8],
                )
                self.segments[subnet] = segment

            if device not in self.segments[subnet].devices:
                self.segments[subnet].devices.append(device)

        except:
            logger.warning(f"Could not assign device {device.ip} to segment")

    def _discover_range(self, ip_range: str):
        """Discover devices in IP range (simulated)"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)

            # Simulate discovery of some devices
            hosts = list(network.hosts())[:20]  # Limit to 20

            for i, ip in enumerate(hosts):
                device_types = ['webcam', 'router', 'nas', 'host', 'printer']
                device_type = device_types[i % len(device_types)]

                self.add_device(
                    ip=str(ip),
                    mac=f"00:11:22:33:44:{i:02x}",
                    hostname=f"{device_type}-{i}.local",
                    device_type=device_type,
                    vendor="Generic Vendor",
                    open_ports=[80, 443] if i % 2 == 0 else [22, 23],
                    services={80: 'http', 443: 'https'} if i % 2 == 0 else {22: 'ssh'},
                )

        except Exception as e:
            logger.error(f"Error discovering range: {e}")

    def _build_topology(self) -> NetworkTopology:
        """Build network topology from discovered devices"""

        # Identify gateways
        gateways = self.identify_gateways()
        gateway_ips = [g.ip for g in gateways]

        # Update segment gateways
        for segment in self.segments.values():
            for device in segment.devices:
                if device.ip in gateway_ips:
                    segment.gateway = device.ip
                    break

        # Build device graph
        device_graph = self.generate_device_graph()

        topology = NetworkTopology(
            topology_id=hashlib.md5(datetime.utcnow().isoformat().encode()).hexdigest()[:8],
            name="Network Topology",
            segments=list(self.segments.values()),
            device_graph=device_graph,
            gateway_devices=gateway_ips,
            total_devices=len(self.devices),
        )

        return topology

    def _count_device_types(self, devices: List[NetworkDevice]) -> Dict[str, int]:
        """Count devices by type"""
        counts = defaultdict(int)
        for device in devices:
            device_type = device.device_type or 'unknown'
            counts[device_type] += 1
        return dict(counts)

    def _count_device_roles(self, devices: List[NetworkDevice]) -> Dict[str, int]:
        """Count devices by role"""
        counts = defaultdict(int)
        for device in devices:
            role = device.role or 'unknown'
            counts[role] += 1
        return dict(counts)

    def _find_subnet_gateway(self, devices: List[NetworkDevice]) -> Optional[str]:
        """Find gateway in subnet"""
        for device in devices:
            if device.role == 'gateway':
                return device.ip
        return None

    def export_topology(
        self,
        output_file: str = "network_topology.json",
        include_graph: bool = True
    ) -> Dict:
        """Export network topology to JSON"""

        if not self.topology:
            logger.warning("No topology available to export")
            return {}

        export_data = {
            'generated_at': datetime.utcnow().isoformat(),
            'topology': asdict(self.topology),
            'statistics': {
                'total_devices': len(self.devices),
                'total_segments': len(self.segments),
                'total_connections': sum(len(d.connections) for d in self.devices.values()),
                'gateway_devices': len(self.topology.gateway_devices),
            },
        }

        if not include_graph:
            export_data['topology'].pop('device_graph', None)

        try:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            logger.info(f"Topology exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting topology: {e}")

        return export_data

    def export_graphviz(self, output_file: str = "network_topology.dot") -> str:
        """
        Export topology as Graphviz DOT format

        Args:
            output_file: Output file path

        Returns:
            DOT format string
        """
        logger.info(f"Exporting topology to Graphviz: {output_file}")

        dot = ["digraph NetworkTopology {"]
        dot.append('  rankdir=TB;')
        dot.append('  node [shape=box];')
        dot.append('')

        # Add nodes
        for ip, device in self.devices.items():
            label = f"{ip}\\n{device.hostname or 'unknown'}\\n({device.role or 'host'})"
            color = self._get_node_color(device.role)

            dot.append(f'  "{ip}" [label="{label}", fillcolor="{color}", style=filled];')

        dot.append('')

        # Add edges
        added_edges = set()
        for ip, device in self.devices.items():
            for connected_ip in device.connections:
                # Avoid duplicate edges
                edge = tuple(sorted([ip, connected_ip]))
                if edge not in added_edges:
                    dot.append(f'  "{ip}" -> "{connected_ip}" [dir=none];')
                    added_edges.add(edge)

        dot.append('}')

        dot_content = '\n'.join(dot)

        try:
            with open(output_file, 'w') as f:
                f.write(dot_content)
            logger.info(f"Graphviz file exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting Graphviz: {e}")

        return dot_content

    def _get_node_color(self, role: Optional[str]) -> str:
        """Get color for node based on role"""
        colors = {
            'gateway': 'lightblue',
            'server': 'lightgreen',
            'webcam': 'lightyellow',
            'host': 'lightgray',
        }
        return colors.get(role or 'host', 'white')


def main():
    """Example usage"""
    print("Network Mapper")
    print("=" * 50)

    # Initialize mapper
    mapper = NetworkMapper()

    # Add devices manually
    print("\n[*] Adding devices to network map...")

    devices_info = [
        {'ip': '192.168.1.1', 'hostname': 'gateway.local', 'device_type': 'router', 'vendor': 'Cisco', 'open_ports': [22, 80, 443]},
        {'ip': '192.168.1.10', 'hostname': 'camera1.local', 'device_type': 'webcam', 'vendor': 'Hikvision', 'open_ports': [80, 554]},
        {'ip': '192.168.1.11', 'hostname': 'camera2.local', 'device_type': 'webcam', 'vendor': 'Dahua', 'open_ports': [80, 37777]},
        {'ip': '192.168.1.20', 'hostname': 'nas.local', 'device_type': 'nas', 'vendor': 'Synology', 'open_ports': [80, 443, 5000]},
        {'ip': '192.168.1.100', 'hostname': 'pc1.local', 'device_type': 'host', 'open_ports': [135, 445]},
    ]

    for device_info in devices_info:
        mapper.add_device(**device_info)

    # Add connections
    print("\n[*] Adding device connections...")
    mapper.add_connection('192.168.1.1', '192.168.1.10')
    mapper.add_connection('192.168.1.1', '192.168.1.11')
    mapper.add_connection('192.168.1.1', '192.168.1.20')
    mapper.add_connection('192.168.1.1', '192.168.1.100')

    # Map network
    print("\n[*] Mapping network topology...")
    topology = mapper.map_network(ip_range="192.168.1.0/24")

    print(f"\n[+] Topology Summary:")
    print(f"  Total Devices: {topology.total_devices}")
    print(f"  Network Segments: {len(topology.segments)}")
    print(f"  Gateway Devices: {len(topology.gateway_devices)}")

    # Show segments
    print("\n[*] Network Segments:")
    for segment in topology.segments:
        print(f"\n  Subnet: {segment.subnet}")
        print(f"  Gateway: {segment.gateway or 'None'}")
        print(f"  Devices: {len(segment.devices)}")

    # Identify gateways
    print("\n[*] Gateway Devices:")
    gateways = mapper.identify_gateways()
    for gateway in gateways:
        print(f"  - {gateway.ip} ({gateway.hostname})")
        print(f"    Connections: {len(gateway.connections)}")

    # Analyze subnet
    print("\n[*] Subnet Analysis:")
    analysis = mapper.analyze_subnet("192.168.1.0/24")
    print(f"  Total Devices: {analysis['total_devices']}")
    print(f"  Utilization: {analysis['utilization']:.1f}%")
    print(f"  Device Types: {analysis['device_types']}")

    # Find critical devices
    print("\n[*] Critical Devices:")
    critical = mapper.find_critical_devices()
    for device in critical[:5]:
        print(f"  - {device.ip} ({device.role})")
        print(f"    Connections: {len(device.connections)}")
        print(f"    Services: {len(device.services)}")

    # Get device neighbors
    print("\n[*] Device Neighbors (192.168.1.1):")
    neighbors = mapper.get_device_neighbors('192.168.1.1', depth=2)
    for depth, ips in neighbors.items():
        if ips:
            print(f"  {depth}: {', '.join(ips)}")

    # Export topology
    print("\n[*] Exporting topology...")
    mapper.export_topology()
    mapper.export_graphviz()
    print("[+] Export completed")


if __name__ == "__main__":
    main()
