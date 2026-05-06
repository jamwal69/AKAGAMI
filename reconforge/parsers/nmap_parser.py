"""
Nmap deterministic parser — reads nmap XML via ElementTree.
Zero LLM. Instant. Deterministic.
"""
import xml.etree.ElementTree as ET
from reconforge.intel.models import Host, Port, IntelBase
from reconforge.utils.logger import get_logger

logger = get_logger("parser.nmap")


class NmapParser:
    """Parses nmap XML output (-oX -) into Host and Port objects."""

    def parse(self, raw: str, mission_id: str,
              source_agent: str) -> list[IntelBase]:
        if not raw or not raw.strip():
            return []
        try:
            return self._parse(raw, mission_id, source_agent)
        except Exception as e:
            logger.warning(f"NmapParser failed: {e} | raw[:200]={raw[:200]!r}")
            return []

    def _parse(self, raw: str, mission_id: str,
               source_agent: str) -> list[IntelBase]:
        # Strip any leading non-XML content (some nmap versions add warnings)
        xml_start = raw.find("<?xml")
        if xml_start == -1:
            xml_start = raw.find("<nmaprun")
        if xml_start > 0:
            raw = raw[xml_start:]

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            logger.warning(f"NmapParser XML parse error: {e}")
            return []

        findings: list[IntelBase] = []

        for host_elem in root.findall(".//host"):
            # Status check — skip down hosts
            status_elem = host_elem.find("status")
            if status_elem is not None and status_elem.get("state") == "down":
                continue

            # IP address
            addr = host_elem.find("address[@addrtype='ipv4']")
            if addr is None:
                addr = host_elem.find("address[@addrtype='ipv6']")
            if addr is None:
                addr = host_elem.find("address")
            if addr is None:
                continue
            ip = addr.get("addr", "")
            if not ip:
                continue

            # Hostname
            hostname_elem = host_elem.find(".//hostname[@type='user']")
            if hostname_elem is None:
                hostname_elem = host_elem.find(".//hostname")
            hostname = hostname_elem.get("name") if hostname_elem is not None else None

            # OS guess
            os_guess = None
            os_confidence = None
            os_match = host_elem.find(".//osmatch")
            if os_match is not None:
                os_guess = os_match.get("name")
                try:
                    os_confidence = float(os_match.get("accuracy", 0)) / 100.0
                except (ValueError, TypeError):
                    os_confidence = None

            host = Host(
                source_agent=source_agent,
                source_tool="nmap",
                confidence=0.95,
                mission_id=mission_id,
                ip=ip,
                hostname=hostname,
                os_guess=os_guess,
                os_confidence=os_confidence,
                tags=self._generate_host_tags(host_elem),
            )
            findings.append(host)

            # Ports — only open ones
            for port_elem in host_elem.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None:
                    continue
                state = state_elem.get("state", "")
                if state not in ("open", "open|filtered"):
                    continue

                portid = port_elem.get("portid", "0")
                protocol = port_elem.get("protocol", "tcp")

                svc = port_elem.find("service")
                service = svc.get("name") if svc is not None else None
                product = (svc.get("product") or "") if svc is not None else ""
                ver = (svc.get("version") or "") if svc is not None else ""
                version = f"{product} {ver}".strip() or None

                # Banner from NSE script output
                banner = None
                for script in port_elem.findall("script"):
                    if script.get("id") in ("banner", "http-server-header",
                                            "ssh-hostkey", "http-title"):
                        banner = script.get("output", "")[:200]
                        break

                try:
                    port_number = int(portid)
                except (TypeError, ValueError):
                    logger.warning(f"NmapParser: skipping invalid port id {portid!r}")
                    continue

                findings.append(Port(
                    source_agent=source_agent,
                    source_tool="nmap",
                    confidence=0.95,
                    mission_id=mission_id,
                    host_id=host.id,
                    port=port_number,
                    protocol=protocol,
                    state=state,
                    service=service,
                    version=version,
                    banner=banner,
                ))

        logger.info(
            f"NmapParser: {sum(1 for f in findings if isinstance(f, Host))} hosts, "
            f"{sum(1 for f in findings if isinstance(f, Port))} open ports")
        return findings

    def _generate_host_tags(self, host_elem) -> list[str]:
        tags = []
        services = set()
        for port_elem in host_elem.findall(".//port"):
            svc = port_elem.find("service")
            if svc is not None:
                services.add(svc.get("name", ""))

        if "http" in services or "https" in services:
            tags.append("web")
        if "ssh" in services:
            tags.append("ssh")
        if "ftp" in services:
            tags.append("ftp")
        if "mysql" in services or "postgresql" in services or "mssql" in services:
            tags.append("database")
        if "smtp" in services or "pop3" in services or "imap" in services:
            tags.append("mail")
        if "dns" in services:
            tags.append("dns")
        if "rdp" in services or "ms-wbt-server" in services:
            tags.append("rdp")
        return tags
