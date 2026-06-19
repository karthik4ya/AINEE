import xml.etree.ElementTree as ET
import json

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []

    for host in root.findall('host'):
        ip = host.find('address[@addrtype="ipv4"]').get('addr')
        
        os_match = host.find('.//osmatch')
        os_name = os_match.get('name') if os_match is not None else 'unknown'

        ports = []
        cpe_list = []

        for port in host.findall('.//port'):
            state = port.find('state').get('state')
            if state != 'open':
                continue

            svc = port.find('service')
            port_info = {
                'port': int(port.get('portid')),
                'proto': port.get('protocol'),
                'service': svc.get('name') if svc is not None else 'unknown',
                'product': svc.get('product', '') if svc is not None else '',
                'version': svc.get('version', '') if svc is not None else '',
                'cpe': ''
            }

            cpe = port.find('.//cpe')
            if cpe is not None:
                port_info['cpe'] = cpe.text
                cpe_list.append(cpe.text)

            ports.append(port_info)

        hosts.append({
            'ip': "10.100.7.250",
            'os': os_name,
            'ports': ports,
            'cpe_list': cpe_list
        })

    return hosts

if __name__ == '__main__':
    hosts = parse_nmap_xml('scan_results.xml')
    print(json.dumps(hosts, indent=2))
