import requests
import time
import dns.resolver
import urllib.parse
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class BaseSecurityModule:
    """Base class for all security testing modules"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.timeout = 10
        self.user_agent = "CyberSec-Toolkit/1.0 (Security Research)"
        
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Base scan method to be overridden by subclasses"""
        raise NotImplementedError("Subclasses must implement scan method")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get common HTTP headers"""
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
    
    def _make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self._get_headers(),
                timeout=self.timeout,
                **kwargs
            )
            return response
        except Exception as e:
            logger.error(f"Request failed for {url}: {e}")
            return None

class ApplicationWalker(BaseSecurityModule):
    """Walk through web application to discover structure and endpoints"""
    
    def __init__(self):
        super().__init__(
            "Application Walker",
            "Discovers application structure, endpoints, and technologies"
        )
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Scan application structure"""
        options = options or {}
        
        results = {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {
                "technologies": [],
                "endpoints": [],
                "forms": [],
                "external_links": [],
                "vulnerabilities": []
            },
            "metadata": {
                "scan_time": time.time(),
                "depth_crawled": 0
            }
        }
        
        try:
            # Initial request to get base page
            response = self._make_request(target)
            if not response:
                results["status"] = "failed"
                results["error"] = "Could not connect to target"
                return results
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Detect technologies
            results["findings"]["technologies"] = self._detect_technologies(response, soup)
            
            # Find forms
            results["findings"]["forms"] = self._extract_forms(soup, target)
            
            # Find links
            links = self._extract_links(soup, target)
            results["findings"]["endpoints"] = links["internal"]
            results["findings"]["external_links"] = links["external"]
            
            # Check for common vulnerabilities
            results["findings"]["vulnerabilities"] = self._check_vulnerabilities(response, soup)
            
            results["metadata"]["depth_crawled"] = 1
            
        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
        
        return results
    
    def _detect_technologies(self, response: requests.Response, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Detect web technologies used"""
        technologies = []
        
        # Check server header
        server = response.headers.get("server", "").lower()
        if server:
            technologies.append({"name": "Server", "value": server, "confidence": "high"})
        
        # Check X-Powered-By header
        powered_by = response.headers.get("x-powered-by", "")
        if powered_by:
            technologies.append({"name": "Framework", "value": powered_by, "confidence": "high"})
        
        # Check meta tags
        for meta in soup.find_all("meta"):
            name = meta.get("name", "").lower()
            content = meta.get("content", "")
            if name in ["generator", "author", "framework"]:
                technologies.append({"name": name.title(), "value": content, "confidence": "medium"})
        
        return technologies
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from the page"""
        forms = []
        
        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action", ""),
                "method": form.get("method", "get").upper(),
                "inputs": [],
                "has_csrf": False
            }
            
            # Make action absolute
            if form_data["action"]:
                form_data["action"] = urllib.parse.urljoin(base_url, form_data["action"])
            else:
                form_data["action"] = base_url
            
            # Extract input fields
            for input_field in form.find_all(["input", "textarea", "select"]):
                field_data = {
                    "name": input_field.get("name", ""),
                    "type": input_field.get("type", "text"),
                    "required": input_field.has_attr("required"),
                    "value": input_field.get("value", "")
                }
                
                # Check for CSRF tokens
                if "csrf" in field_data["name"].lower() or "token" in field_data["name"].lower():
                    form_data["has_csrf"] = True
                
                form_data["inputs"].append(field_data)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Dict[str, List[str]]:
        """Extract internal and external links"""
        internal_links = set()
        external_links = set()
        
        base_domain = urllib.parse.urlparse(base_url).netloc
        
        for link in soup.find_all("a", href=True):
            href = link["href"]
            absolute_url = urllib.parse.urljoin(base_url, href)
            parsed_url = urllib.parse.urlparse(absolute_url)
            
            if parsed_url.netloc == base_domain or not parsed_url.netloc:
                internal_links.add(absolute_url)
            else:
                external_links.add(absolute_url)
        
        return {
            "internal": list(internal_links),
            "external": list(external_links)
        }
    
    def _check_vulnerabilities(self, response: requests.Response, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        # Check for missing security headers
        security_headers = [
            "X-Frame-Options",
            "X-XSS-Protection", 
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security"
        ]
        
        for header in security_headers:
            if header.lower() not in [h.lower() for h in response.headers.keys()]:
                vulnerabilities.append({
                    "type": "Missing Security Header",
                    "severity": "medium",
                    "description": f"Missing {header} header",
                    "recommendation": f"Add {header} header to improve security"
                })
        
        return vulnerabilities

class ContentDiscovery(BaseSecurityModule):
    """Discover hidden content and directories"""
    
    def __init__(self):
        super().__init__(
            "Content Discovery",
            "Discovers hidden files, directories, and backup files"
        )
        
        self.common_files = [
            "robots.txt", "sitemap.xml", ".htaccess", "web.config",
            "backup.zip", "config.php.bak", ".env"
        ]
        
        self.common_dirs = [
            "admin", "administrator", "login", "backup", "api", "test"
        ]
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Discover hidden content"""
        options = options or {}
        
        results = {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {
                "files_found": [],
                "directories_found": [],
                "interesting_responses": []
            },
            "metadata": {
                "scan_time": time.time(),
                "requests_made": 0
            }
        }
        
        # Ensure target ends with /
        if not target.endswith('/'):
            target += '/'
        
        try:
            # Check common files
            for filename in self.common_files:
                url = target + filename
                response = self._make_request(url)
                results["metadata"]["requests_made"] += 1
                
                if response and response.status_code == 200:
                    results["findings"]["files_found"].append({
                        "url": url,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "size": len(response.content)
                    })
                elif response and response.status_code in [403, 401]:
                    results["findings"]["interesting_responses"].append({
                        "url": url,
                        "status_code": response.status_code,
                        "description": "Access denied - file may exist"
                    })
                
                time.sleep(0.1)  # Rate limiting
            
            # Check common directories
            for dirname in self.common_dirs:
                url = target + dirname + "/"
                response = self._make_request(url)
                results["metadata"]["requests_made"] += 1
                
                if response and response.status_code == 200:
                    results["findings"]["directories_found"].append({
                        "url": url,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "size": len(response.content)
                    })
                elif response and response.status_code in [403, 401]:
                    results["findings"]["interesting_responses"].append({
                        "url": url,
                        "status_code": response.status_code,
                        "description": "Access denied - directory may exist"
                    })
                
                time.sleep(0.1)  # Rate limiting
                
        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
        
        return results

class SubdomainEnumerator(BaseSecurityModule):
    """Enumerate subdomains of a target domain"""
    
    def __init__(self):
        super().__init__(
            "Subdomain Enumeration",
            "Discovers subdomains using DNS queries and wordlists"
        )
        
        self.common_subdomains = [
            "www", "mail", "ftp", "admin", "test", "dev", "api", "app"
        ]
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Enumerate subdomains"""
        options = options or {}
        
        # Extract domain from URL if full URL provided
        if target.startswith('http'):
            domain = urllib.parse.urlparse(target).netloc
        else:
            domain = target
        
        results = {
            "target": domain,
            "module": self.name,
            "status": "completed",
            "findings": {
                "subdomains_found": [],
                "dns_records": []
            },
            "metadata": {
                "scan_time": time.time(),
                "queries_made": 0
            }
        }
        
        try:
            # Check common subdomains
            for subdomain in self.common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                
                try:
                    # Try DNS resolution
                    answers = dns.resolver.resolve(full_domain, 'A')
                    ips = [str(answer) for answer in answers]
                    
                    results["findings"]["subdomains_found"].append({
                        "subdomain": full_domain,
                        "ips": ips,
                        "method": "dns_resolution"
                    })
                    
                except dns.resolver.NXDOMAIN:
                    pass  # Subdomain doesn't exist
                except Exception as e:
                    logger.debug(f"Error checking {full_domain}: {e}")
                
                results["metadata"]["queries_made"] += 1
                time.sleep(0.1)  # Rate limiting
        
        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
        
        return results

# Placeholder classes for remaining modules
class AuthBypass(BaseSecurityModule):
    def __init__(self):
        super().__init__("Authentication Bypass", "Tests for authentication bypass techniques")
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {"bypass_attempts": []},
            "metadata": {"scan_time": time.time()}
        }

class IDORDetector(BaseSecurityModule):
    def __init__(self):
        super().__init__("IDOR Detection", "Detects Insecure Direct Object Reference vulnerabilities")
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {"potential_idor": []},
            "metadata": {"scan_time": time.time()}
        }

class FileInclusionScanner(BaseSecurityModule):
    def __init__(self):
        super().__init__("File Inclusion Scanner", "Tests for LFI/RFI vulnerabilities")
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {"lfi_tests": [], "rfi_tests": []},
            "metadata": {"scan_time": time.time()}
        }

class SSRFDetector(BaseSecurityModule):
    def __init__(self):
        super().__init__("SSRF Detector", "Tests for Server-Side Request Forgery")
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {"ssrf_tests": []},
            "metadata": {"scan_time": time.time()}
        }

class XSSScanner(BaseSecurityModule):
    def __init__(self):
        super().__init__("XSS Scanner", "Tests for Cross-Site Scripting vulnerabilities")
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {"xss_tests": []},
            "metadata": {"scan_time": time.time()}
        }

class RaceConditionTester(BaseSecurityModule):
    def __init__(self):
        super().__init__("Race Condition Tester", "Tests for race condition vulnerabilities")
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {"race_condition_tests": []},
            "metadata": {"scan_time": time.time()}
        }

class CommandInjectionTester(BaseSecurityModule):
    def __init__(self):
        super().__init__("Command Injection Tester", "Tests for command injection vulnerabilities")
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {"command_injection_tests": []},
            "metadata": {"scan_time": time.time()}
        }

class SQLInjectionScanner(BaseSecurityModule):
    def __init__(self):
        super().__init__("SQL Injection Scanner", "Tests for SQL injection vulnerabilities")
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "target": target,
            "module": self.name,
            "status": "completed",
            "findings": {"sql_injection_tests": []},
            "metadata": {"scan_time": time.time()}
        }

# Module registry
MODULES = {
    "application_walker": ApplicationWalker(),
    "content_discovery": ContentDiscovery(),
    "subdomain_enum": SubdomainEnumerator(),
    "auth_bypass": AuthBypass(),
    "idor_detection": IDORDetector(),
    "file_inclusion": FileInclusionScanner(),
    "ssrf_detection": SSRFDetector(),
    "xss_scanner": XSSScanner(),
    "race_conditions": RaceConditionTester(),
    "command_injection": CommandInjectionTester(),
    "sql_injection": SQLInjectionScanner(),
}
