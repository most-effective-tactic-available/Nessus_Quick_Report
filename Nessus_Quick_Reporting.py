import os
import xml.etree.ElementTree as ET

def parse_nessus_file(nessus_file):
    """
    Parses a .nessus file and returns a list of vulnerabilities and a list of hosts.

    Args:
        nessus_file: The path to the .nessus file.

    Returns:
        A tuple of lists, where the first list contains dictionaries representing the vulnerabilities
        and the second list contains dictionaries representing the hosts.

    Raises:
        FileNotFoundError: If the .nessus file does not exist.
        ParseError: If the .nessus file is not well-formed.
    """

    if not os.path.isfile(nessus_file):
        raise FileNotFoundError(f"The file {nessus_file} does not exist.")

    try:
        tree = ET.parse(nessus_file)
    except ET.ParseError as e:
        raise ParseError(f"Error: Failed to parse {nessus_file}: {e}")

    root = tree.getroot()

    vulnerabilities = []
    for vuln in root.findall("vulnerabilities/vulnerability"):
        vulnerabilities.append({
            "name": vuln.get("plugin_name"),
            "description": vuln.get("plugin_description")
        })

    hosts = []
    for host in root.findall("Report/ReportHost"):
        hosts.append({
            "name": host.get("name"),
            "ip_address": host.get("ip_address")
        })

    return vulnerabilities, hosts

def get_vulnerable_hosts(nessus_file):
    """
    Gets a list of all the hosts that are vulnerable from a .nessus file.

    Args:
        nessus_file: The path to the .nessus file.

    Returns:
        A list of dictionaries representing the vulnerable hosts, each containing the host details
        and the associated vulnerability details.

    Raises:
        FileNotFoundError: If the .nessus file does not exist.
        ParseError: If the .nessus file is not well-formed.
    """

    vulnerabilities, all_hosts = parse_nessus_file(nessus_file)
    if vulnerabilities is None or all_hosts is None:
        return None

    vulnerability_lookup = {vuln["name"]: vuln for vuln in vulnerabilities}

    vulnerable_hosts = []
    for host in all_hosts:
        if host["name"] in vulnerability_lookup:
            vulnerability = vulnerability_lookup[host["name"]]
            vulnerable_hosts.append({
                "name": host["name"],
                "ip_address": host["ip_address"],
                "vulnerability": vulnerability
            })

    return vulnerable_hosts

def write_vulnerable_hosts_to_xml(vulnerable_hosts, filename):
    """
    Writes a list of vulnerable hosts to an XML file.

    Args:
        vulnerable_hosts: A list of dictionaries representing
