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

# Initialize colorama for colored output
init(autoreset=True)

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
    ):
        """
        Initialize the IDORChecker with the target URL and configuration.
        """
        self.url = url
        self.base_url, self.params = self._parse_url(url)
        self.delay = delay
        self.headers = headers or {}
        self.proxy = proxy
        self.verbose = verbose
        self.sensitive_keywords = sensitive_keywords or [
            "password", "email", "token", "ssn", "credit_card"
        ]
        self.session = requests.Session()
        self.rate_limit_detected = False
        self.timeout = timeout
        self.max_retries = max_retries
        self.payload_history = []
        self.logger = logger if logger else print
        self.payload_history_lock = Lock()
        self.max_workers = max_workers
        self.baseline_response = None
        self.baseline_id = None
        self.baseline_data = None
        self.baseline_hash = None  # For quick comparison

    def login(self, login_url: str, credentials: Dict, method: str = "POST") -> bool:
        """
        Perform a login request to obtain session cookies or tokens.
        """
        try:
            response = self.session.request(
                method=method.upper(),
                url=login_url,
                data=credentials,
                headers=self.headers,
                proxies=self.proxy,
                timeout=self.timeout,
            )
            if response.status_code in (200, 302):
                self.logger(f"{Fore.GREEN}Login successful.{Style.RESET_ALL}")
                self._set_baseline_after_login()
                return True
            else:
                self.logger(f"{Fore.RED}Login failed. Status Code: {response.status_code}{Style.RESET_ALL}")
                return False
        except requests.RequestException as e:
            self.logger(f"{Fore.RED}Error during login: {e}{Style.RESET_ALL}")
            return False

    def _set_baseline_after_login(self):
        """
        Fetch current user's profile to set baseline ID and response after login.
        """
        try:
            response = self._send_request(self.params, "GET")
            if response and response.status_code == 200:
                self.baseline_response = response
                self.baseline_data = self._parse_response_as_json(response.text)
                self.baseline_hash = self._hash_response(response.text)
                if self.baseline_data and "id" in self.baseline_data:
                    self.baseline_id = str(self.baseline_data["id"])
                elif "user_id" in self.params:
                    self.baseline_id = self.params["user_id"]
                self.logger(f"{Fore.CYAN}Baseline set for authorized user ID: {self.baseline_id}{Style.RESET_ALL}")
            else:
                self.logger(f"{Fore.YELLOW}Could not set baseline after login.{Style.RESET_ALL}")
        except Exception as e:
            self.logger(f"{Fore.RED}Error setting baseline: {e}{Style.RESET_ALL}")

    def _parse_url(self, url: str) -> tuple:
        """
        Parse the URL into base URL and query parameters.
        """
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL format")
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            params = parse_qs(parsed_url.query)
            return base_url, params
        except Exception as e:
            self.logger(f"{Fore.RED}Error parsing URL: {e}{Style.RESET_ALL}")
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
                    return self._get_default_payloads(os.path.basename(filename).split('.')[0])
                return payloads
        except FileNotFoundError:
            self.logger(f"{Fore.RED}Warning: Payload file {filename} not found. Using default payloads.{Style.RESET_ALL}")
            return self._get_default_payloads(os.path.basename(filename).split('.')[0])

    def _get_default_payloads(self, payload_type: str) -> List[str]:
        """
        Get default payloads if file is missing or empty.
        """
        defaults = {
            "sql": ["' OR '1'='1' --", "' OR '1'='1'#", "' OR '1'='1'/*", "' OR IF(1=1, SLEEP(5), 0) --"],
            "xss": ["<script>alert('XSS')</script>", "<svg onload=alert('XSS')>", '"><script>alert(\'XSS\')</script>', "<IMG SRC=\"javascript:alert('XSS');\">"],
            "xml": ["<user><name>John</name><password>' OR '1'='1'</password></user>", "<?xml version=\"1.0\"?>", "<!DOCTYPE root [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>", "<root>&xxe;</root>"],
        }
        return defaults.get(payload_type, [])

    def _generate_payloads(self, param: str, values: List[str]) -> List[Dict]:
        """
        Generate payloads for the specified parameter.
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
                *[{**new_params, "xml": xml} for xml in self._payload_cache["xml"]],
            ])
        return payloads

    def _generate_random_string(self, length: int) -> str:
        """
        Generate a random string of specified length.
        """
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def _send_request(self, params: Dict, method: str = "GET") -> Optional[requests.Response]:
        """
        Send a request with the given parameters and method.
        """
        retries = 0
        while retries < self.max_retries:
            try:
                request_args = {"headers": self.headers, "proxies": self.proxy, "timeout": self.timeout}
                if method.upper() == "GET":
                    response = self.session.get(self.base_url, params=params, **request_args)
                elif method.upper() in ("POST", "PUT", "DELETE"):
                    response = self.session.request(method.upper(), self.base_url, data=params, **request_args)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                return response
            except requests.RequestException as e:
                retries += 1
                delay = self.delay * (2 ** retries) + random.uniform(0, 1)  # Add random jitter for rate limiting avoidance
                self.logger(f"{Fore.YELLOW}Request failed (Attempt {retries}/{self.max_retries}): {e}{Style.RESET_ALL}")
                time.sleep(delay)
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
        Compare baseline and test responses for structure, content, and similarity.
        """
        baseline_data = self._parse_response_as_json(baseline_text)
        test_data = self._parse_response_as_json(test_text)
        text_similarity = SequenceMatcher(None, baseline_text, test_text).ratio()
        structure_similarity = 0.0
        content_similarity = 0.0
        if baseline_data and test_data:
            structure_similarity = self._compare_response_structure(baseline_data, test_data)
            content_similarity = self._compare_response_content(baseline_data, test_data)
        return {
            "text_similarity": text_similarity,
            "structure_similarity": structure_similarity,
            "content_similarity": content_similarity
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
        Check if response contains sensitive data.
        """
        for keyword in self.sensitive_keywords:
            if re.search(rf'\b{keyword}\b', response_content, re.IGNORECASE):
                return True
        if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response_content):
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
            full_url = self._construct_url(payload)
            start_time = time.time()
            response = self.session.request(
                method=method.upper(),
                url=self.base_url,
                params=payload if method.upper() == "GET" else None,
                data=payload if method.upper() != "GET" else None,
                headers=self.headers,
                proxies=self.proxy,
                timeout=self.timeout,
            )
            response_time = time.time() - start_time

            if self._is_rate_limited(response):
                self.rate_limit_detected = True
                self.logger(f"{Fore.YELLOW}Rate limit detected for {full_url}{Style.RESET_ALL}")
                return None

            comparison = self._compare_responses(self.baseline_response.text, response.text) if self.baseline_response else {}
            sensitive_data_detected = self._contains_sensitive_data(response.text)
            idor_detected = self._detect_idor(comparison, response.status_code)
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
                "comparison": comparison
            }

            if sensitive_data_detected or idor_detected or sql_injection_detected or xss_detected or xml_detected:
                self.logger(
                    f"{Fore.RED}Vulnerability detected at {full_url}: "
                    f"Sensitive: {sensitive_data_detected}, IDOR: {idor_detected}, "
                    f"SQL: {sql_injection_detected}, XSS: {xss_detected}, XML: {xml_detected}{Style.RESET_ALL}"
                )
            elif self.verbose:
                self.logger(f"{Fore.GREEN}Tested {full_url} (Status: {response.status_code}){Style.RESET_ALL}")

            return result
        except requests.RequestException as e:
            self.logger(f"{Fore.RED}Request failed for {full_url}: {e}{Style.RESET_ALL}")
            return None

    def _detect_idor(self, comparison: Dict, status_code: int) -> bool:
        """
        Detect IDOR based on response comparison.
        """
        if status_code == 200:
            if comparison.get("structure_similarity", 0) > 0.8 and comparison.get("content_similarity", 0) < 0.9:
                return True
            if comparison.get("text_similarity", 0) > 0.8:
                return True
        return False

    def _detect_sql_injection(self, content: str, status_code: int, response_time: float) -> bool:
        """
        Detect SQL injection vulnerabilities, including blind SQLi.
        """
        sql_errors = [
            "sql syntax", "mysql_fetch", "unclosed quotation mark", "unknown column",
            "division by zero", "error in your SQL syntax", "You have an error in your SQL syntax"
        ]
        if status_code >= 500 or any(error in content.lower() for error in sql_errors):
            return True
        if response_time > 5:  # Threshold for blind SQLi delay
            return True
        return False

    def _detect_xss(self, content: str, payload: Dict) -> bool:
        """
        Detect XSS vulnerabilities by checking for unescaped payload reflection.
        """
        xss_payload = payload.get("xss")
        if xss_payload and xss_payload in content:
            # Check if it's unescaped (not &lt;script&gt;, etc.)
            if re.search(re.escape(xss_payload), content, re.IGNORECASE):
                return True
        return False

    def _detect_xml_injection(self, content: str, payload: Dict) -> bool:
        """
        Detect XML injection vulnerabilities, including XXE.
        """
        xml_payload = payload.get("xml")
        if xml_payload and xml_payload in content:
            # Check for entity expansion (e.g., file content in response)
            if re.search(r'/etc/passwd|root|bin|usr', content, re.IGNORECASE):
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

        # Set baseline if not already set
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

        # Scan with ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self._test_payload, payload, method) for payload in payloads]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    with self.payload_history_lock:
                        self.payload_history.append(result)
                    results.append(result)

        # Save results
        if output_file:
            if output_format == "csv":
                self._save_results_csv(results, output_file)
            elif output_format == "json":
                self._save_results_json(results, output_file)
            else:
                self._save_results_txt(results, output_file)
            self.logger(f"{Fore.GREEN}Results saved to {output_file}{Style.RESET_ALL}")

        # Display summary
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
            vulnerabilities = [r for r in results if r["sensitive_data_detected"] or r["idor_detected"] or r["sql_injection_detected"] or r["xss_detected"] or r["xml_detected"]]
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
                    f.write("-" * 40 + "\n")
            else:
                f.write("No vulnerabilities detected.\n")

    def _save_results_csv(self, results: List[Dict], output_file: str):
        """
        Save results to a CSV file.
        """
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Payload", "Status Code", "Sensitive Data", "IDOR", "SQL Injection", "XSS", "XML", "Response Time", "Comparison"])
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
        vulnerable_count = sum(1 for r in results if r["sensitive_data_detected"] or r["idor_detected"] or r["sql_injection_detected"] or r["xss_detected"] or r["xml_detected"])
        safe_count = len(results) - vulnerable_count
        labels = ["Vulnerable", "Safe"]
        sizes = [vulnerable_count, safe_count]
        colors = ["red", "green"]

        plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.title("Vulnerability Summary")
        plt.axis('equal')
        plt.show()

        table_data = [
            [r["url"], r["status_code"], r["sensitive_data_detected"], r["idor_detected"], r["sql_injection_detected"], r["xss_detected"], r["xml_detected"]]
            for r in results if r["sensitive_data_detected"] or r["idor_detected"] or r["sql_injection_detected"] or r["xss_detected"] or r["xml_detected"]
        ]
        headers = ["URL", "Status Code", "Sensitive Data", "IDOR", "SQL Injection", "XSS", "XML"]
        if table_data:
            print(tabulate(table_data, headers=headers, tablefmt="grid"))

    def _display_summary(self, results: List[Dict]):
        """
        Display a clean summary of scan results.
        """
        vulnerabilities = [r for r in results if r["sensitive_data_detected"] or r["idor_detected"] or r["sql_injection_detected"] or r["xss_detected"] or r["xml_detected"]]
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
                self.logger("-" * 40)
        else:
            self.logger(f"{Fore.GREEN}No vulnerabilities detected.{Style.RESET_ALL}")

        if results and self.verbose:
            visualize = input("\nVisualize results? (y/n): ").strip().lower()
            if visualize == "y":
                self.visualize_results(results)
