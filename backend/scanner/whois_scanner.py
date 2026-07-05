import asyncio
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


async def scan_whois_dns(target: str) -> Dict[str, Any]:
    """Gather WHOIS and DNS information for a target."""
    results = {
        "dns_info": {
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "ns_records": [],
            "cname_records": [],
        },
        "whois_data": {},
        "vulnerabilities": [],
    }

    # Clean target
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # DNS Reconnaissance
    try:
        import dns.resolver
        import dns.exception

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        # A records
        try:
            answers = resolver.resolve(hostname, "A")
            results["dns_info"]["a_records"] = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # MX records
        try:
            answers = resolver.resolve(hostname, "MX")
            results["dns_info"]["mx_records"] = [str(rdata.exchange) for rdata in answers]
        except Exception:
            pass

        # TXT records
        try:
            answers = resolver.resolve(hostname, "TXT")
            txt_records = []
            for rdata in answers:
                for string in rdata.strings:
                    txt_records.append(string.decode("utf-8", errors="ignore"))
            results["dns_info"]["txt_records"] = txt_records

            # Analyze TXT records
            full_txt = " ".join(txt_records).lower()
            if "spf" not in full_txt and results["dns_info"]["mx_records"]:
                results["vulnerabilities"].append({
                    "title": "Missing SPF Record",
                    "severity": "medium",
                    "description": "No SPF (Sender Policy Framework) record found — domain may be used for email spoofing",
                    "recommendation": "Add an SPF TXT record to restrict which servers can send email for your domain",
                    "category": "Email Security",
                    "affected": hostname,
                })
            if "dmarc" not in full_txt and results["dns_info"]["mx_records"]:
                results["vulnerabilities"].append({
                    "title": "Missing DMARC Record",
                    "severity": "medium",
                    "description": "No DMARC policy found — email authentication not enforced",
                    "recommendation": "Add _dmarc TXT record with p=quarantine or p=reject policy",
                    "category": "Email Security",
                    "affected": hostname,
                })
        except Exception:
            pass

        # NS records
        try:
            answers = resolver.resolve(hostname, "NS")
            results["dns_info"]["ns_records"] = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # CNAME records
        try:
            answers = resolver.resolve(hostname, "CNAME")
            results["dns_info"]["cname_records"] = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # Check for zone transfer vulnerability
        for ns in results["dns_info"]["ns_records"][:2]:
            try:
                import dns.zone
                import dns.query
                ns_clean = ns.rstrip(".")
                zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, hostname, timeout=5))
                if zone:
                    results["vulnerabilities"].append({
                        "title": "DNS Zone Transfer Allowed",
                        "severity": "critical",
                        "description": f"Nameserver {ns} allows zone transfer (AXFR) — exposes all DNS records",
                        "recommendation": "Restrict zone transfers to authorized secondary nameservers only",
                        "category": "DNS Security",
                        "affected": ns,
                        "cvss_score": 9.1,
                        "cve_id": "CVE-1999-0532",
                    })
            except Exception:
                pass  # Zone transfer refused (expected/good)

    except ImportError:
        logger.warning("dnspython not installed, skipping DNS reconnaissance")
    except Exception as e:
        logger.error(f"DNS scan error: {e}")

    # WHOIS Lookup
    try:
        import whois
        loop = asyncio.get_event_loop()
        whois_data = await loop.run_in_executor(None, lambda: whois.whois(hostname))

        if whois_data:
            results["whois_data"] = {
                "registrar": str(whois_data.registrar) if whois_data.registrar else "Unknown",
                "creation_date": str(whois_data.creation_date[0] if isinstance(whois_data.creation_date, list)
                                     else whois_data.creation_date) if whois_data.creation_date else "Unknown",
                "expiration_date": str(whois_data.expiration_date[0] if isinstance(whois_data.expiration_date, list)
                                       else whois_data.expiration_date) if whois_data.expiration_date else "Unknown",
                "name_servers": [str(ns) for ns in whois_data.name_servers] if whois_data.name_servers else [],
                "status": [str(s) for s in whois_data.status] if isinstance(whois_data.status, list)
                          else [str(whois_data.status)] if whois_data.status else [],
                "country": str(whois_data.country) if whois_data.country else "Unknown",
                "org": str(whois_data.org) if whois_data.org else "Unknown",
            }
    except ImportError:
        logger.warning("python-whois not installed, skipping WHOIS lookup")
    except Exception as e:
        logger.warning(f"WHOIS lookup failed: {e}")

    return results
