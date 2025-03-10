import argparse
import json
from core.banner import banner
from core.IDORChecker import IDORChecker  # Assuming you separate the IDORChecker class
from core.interactive import interactive_mode  # Import the GUI function

def main():
    banner()
    print("")
    
    parser = argparse.ArgumentParser(
        description="Ultimate IDOR Vulnerability Checker",
        prog="""npython IDOR-Forge.py -u "https://example.com/api/resource?id=1" -p -m GET --proxy "http://127.0.0.1:8080" -v -o results.csv --output-format csv\n       python IDOR-Forge.py -u http://example.com/resource?id=1 -p -m GET --output results.csv --output-format csv --test-values [100,200,300] --sensitive-keywords ["password", "email"]
    """)
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
    parser.add_argument("-Rv", "--report-and-visualize", action="store_true", help="Enable reporting and visualization")

    args = parser.parse_args()

    if args.interactive:
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

    # Initialize IDORChecker
    checker = IDORChecker(
        args.url,
        delay=args.delay,
        headers=headers,
        proxy=proxy,
        verbose=args.verbose,
        sensitive_keywords=sensitive_keywords,
    )

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

    # Generate report and visualize results if -Rv is specified
    if args.report_and_visualize:
        if not results:
            print(f"{Fore.YELLOW}No results to report or visualize.{Style.RESET_ALL}")
            return

        # Generate a detailed report
        report_output = "idor_report.txt"  # Default report file name
        checker.generate_report(results, report_output, format_type="txt")
        print(f"{Fore.GREEN}Report generated: {report_output}{Style.RESET_ALL}")

        # Visualize results
        print(f"{Fore.CYAN}Generating visualizations...{Style.RESET_ALL}")
        checker.visualize_results(results)

if __name__ == "__main__":
    main()
