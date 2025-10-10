#!/usr/bin/env python3
"""Generate simple HTML visualization of network discovery results."""
import base64
import io
import os
import sys
import xml.etree.ElementTree as ET


def parse_nmap(xml_path):
    hosts = {}
    tree = ET.parse(xml_path)
    for host in tree.findall('host'):
        status = host.find('status').get('state')
        if status != 'up':
            continue
        addr_elem = host.find('address')
        if addr_elem is None:
            continue
        ip_addr = addr_elem.get('addr')
        ports = [p.get('portid') for p in host.findall("ports/port[state[@state='open']]")]
        hosts[ip_addr] = ports
    return hosts


def build_chart(port_counts):
    try:
        import matplotlib.pyplot as plt
    except Exception:
        return ''
    if not port_counts:
        return ''
    sorted_items = sorted(port_counts.items(), key=lambda x: int(x[0]))
    ports, counts = zip(*sorted_items)
    fig, ax = plt.subplots()
    ax.bar(ports, counts)
    ax.set_xlabel('Port')
    ax.set_ylabel('Hosts')
    ax.set_title('Open Port Distribution')
    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format='png')
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode('ascii')


def build_html(hosts, img_data, out_path):
    rows = ''.join(
        f"<tr><td>{h}</td><td>{', '.join(p) if p else 'None'}</td></tr>" for h, p in hosts.items()
    )
    html = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='UTF-8'><title>Network Discovery Report</title></head><body>",
        "<h1>Network Discovery Report</h1>",
        "<h2>Open Ports by Host</h2>",
        "<table border='1'><tr><th>Host</th><th>Open Ports</th></tr>",
        rows,
        "</table>",
    ]
    if img_data:
        html.extend(
            [
                "<h2>Port Distribution</h2>",
                f"<img src='data:image/png;base64,{img_data}' alt='Port Distribution'>",
            ]
        )
    else:
        html.append("<p>matplotlib not available or no port data to visualize.</p>")
    html.append("</body></html>")
    with open(out_path, 'w') as f:
        f.write('\n'.join(html))


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} OUTPUT_DIR")
        sys.exit(1)
    out_dir = sys.argv[1]
    xml_file = os.path.join(out_dir, 'network_services.xml')
    if not os.path.exists(xml_file):
        print(f"Missing {xml_file}")
        return
    hosts = parse_nmap(xml_file)
    port_counts = {}
    for ports in hosts.values():
        for p in ports:
            port_counts[p] = port_counts.get(p, 0) + 1
    img_data = build_chart(port_counts)
    out_html = os.path.join(out_dir, 'network_discovery_report.html')
    build_html(hosts, img_data, out_html)


if __name__ == '__main__':
    main()
