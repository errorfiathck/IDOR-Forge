import argparse
from core.IDORChecker import IDORChecker  # Assuming you separate the IDORChecker class
from core.banner import banner
import json
from colorama import Fore, Style, init

def main():
    banner()

    parser = argparse.ArgumentParser(description="Ultimate IDOR Vulnerability Checker")
    parser.add_argument("-u", "--url", help="Target URL to test for IDOR vulnerabilities")
    parser.add_argument("-p", "--parameters", action="store_true", help="Scan all parameters in the URL")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method to use (GET, POST, PUT, DELETE)")
    parser.add_argument("-d", "--delay", type=float, default=1, help="Delay between requests (in seconds)")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("--output-format", choices=["txt", "csv", "json"], default="txt", help="Output file format")
    parser.add_argument("--headers", help="Custom headers in JSON format")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--test-values", help="Custom test values in JSON format")
    parser.add_argument("--sensitive-keywords", help="Custom sensitive keywords in JSON format")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive GUI mode")
    parser.add_argument("--login-url", help="URL for the login page")
    parser.add_argument("--credentials", help="Login credentials in JSON format (e.g., '{\"username\": \"admin\", \"password\": \"password\"}')")
    parser.add_argument("--login-method", default="POST", help="HTTP method to use for login (default: POST)")
    parser.add_argument("--max-workers", type=int, default=5, help="Number of threads for multi-threaded scanning")


    args = parser.parse_args()

    if args.interactive:
        from core.interactive import interactive_mode
        interactive_mode()
        return

    # Parse custom headers
    headers = {}
    if args.headers:
        try:
            headers = json.loads(args.headers)  # Convert JSON string to dictionary
        except json.JSONDecodeError as e:
            print(f"Error parsing headers: {e}")
            return

    # Parse proxy configuration
    proxy = None
    if args.proxy:
        proxy = {"http": args.proxy, "https": args.proxy}

    # Parse custom test values
    test_values = [1, 2, 3, 4, 5]  # Default test values
    if args.test_values:
        try:
            test_values = json.loads(args.test_values)  # Convert JSON string to list
        except json.JSONDecodeError as e:
            print(f"Error parsing test values: {e}")
            return

    # Parse custom sensitive keywords
    sensitive_keywords = None
    if args.sensitive_keywords:
        try:
            sensitive_keywords = json.loads(args.sensitive_keywords)
        except json.JSONDecodeError as e:
            print(f"Error parsing sensitive keywords: {e}")
            return

    # Parse login credentials
    credentials = None
    if args.credentials:
        try:
            credentials = json.loads(args.credentials)
        except json.JSONDecodeError as e:
            print(f"Error parsing credentials: {e}")
            return

    # Initialize IDORChecker
    checker = IDORChecker(
        args.url,
        delay=args.delay,
        headers=headers,
        proxy=proxy,
        verbose=args.verbose,
        sensitive_keywords=sensitive_keywords,
    )

    # Perform login if credentials are provided
    if args.login_url and credentials:
        if not checker.login(args.login_url, credentials, method=args.login_method):
            print(f"{Fore.RED}Failed to log in. Exiting...{Style.RESET_ALL}")
            return

    # If -p switch is used, scan all parameters in the URL
    if args.parameters:
        results = []
        for param in checker.params.keys():
            print(f"Scanning parameter: {param}")
            results.extend(
                checker.check_idor(
                    param,
                    test_values,
                    method=args.method,
                    output_file=args.output,
                    output_format=args.output_format,
                )
            )
    else:
        # If -p is not used, test a single parameter (e.g., 'id')
        param_to_test = "id"
        results = checker.check_idor(
            param_to_test,
            test_values,
            method=args.method,
            output_file=args.output,
            output_format=args.output_format,
        )

    # Generate report and visualize results if requested
    if hasattr(checker, "generate_report"):
        checker.generate_report(results, "idor_report.txt", format_type="txt")

    if hasattr(checker, "visualize_results"):
        visualize = input("Do you want to visualize the results? (y/n): ").strip().lower()
        if visualize == "y":
            checker.visualize_results(results)

if __name__ == "__main__":
    main()
