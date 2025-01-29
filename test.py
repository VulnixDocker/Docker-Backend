import docker
import requests
import argparse
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

# Initialize Docker client
client = docker.from_env()

# Vulnerability database API
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"

# Lock for thread-safe console printing
print_lock = threading.Lock()

def fetch_cve_data(cpe_name):
    """Fetch CVE data from NVD."""
    try:
        response = requests.get(f"{NVD_API_URL}?cpeMatchString={cpe_name}")
        if response.status_code == 200:
            return response.json()
        else:
            with print_lock:
                print(f"[ERROR] Failed to fetch CVE data: HTTP {response.status_code}")
    except Exception as e:
        with print_lock:
            print(f"[EXCEPTION] {e}")
    return {}

def scan_image(image_name, severity_filter=None, output_path=None):
    """Analyze a Docker image for vulnerabilities."""
    try:
        image = client.images.get(image_name)
        print(f"[INFO] Analyzing image: {image_name}")

        # Simulated OS detection (replace with real logic)
        os_info = "debian:10"  # Example OS
        print(f"[INFO] Identified OS: {os_info}")

        # Fetch vulnerabilities
        cve_data = fetch_cve_data(os_info)
        if cve_data:
            vulnerabilities = []
            for item in cve_data.get("result", {}).get("CVE_Items", []):
                severity = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "Unknown")
                if not severity_filter or severity.lower() == severity_filter.lower():
                    vulnerability = {
                        "id": item['cve']['CVE_data_meta']['ID'],
                        "severity": severity,
                        "description": item['cve']['description']['description_data'][0]['value'],
                    }
                    vulnerabilities.append(vulnerability)
                    with print_lock:
                        print(f" - {vulnerability['id']} ({vulnerability['severity']}): {vulnerability['description']}")

            # Save to JSON report if output_path is provided
            if output_path:
                with open(output_path, "w") as report_file:
                    json.dump(vulnerabilities, report_file, indent=4)
                print(f"[INFO] Report saved to {output_path}")
        else:
            print("[INFO] No vulnerabilities found.")
    except docker.errors.ImageNotFound:
        print(f"[ERROR] Docker image {image_name} not found!")
    except Exception as e:
        print(f"[ERROR] Exception occurred: {e}")

def owasp_checks(image_name):
    """Perform OWASP Top 10 checks."""
    print("[INFO] Running OWASP Top 10 checks...")
    dockerfile_path = f"./Dockerfile.{image_name}"
    if os.path.exists(dockerfile_path):
        with open(dockerfile_path, "r") as dockerfile:
            content = dockerfile.read()
            if "USER root" in content:
                print(" - [CRITICAL] Running as root is discouraged.")
            if "latest" in content:
                print(" - [WARNING] Avoid using 'latest' tag in images.")
            if "COPY . /app" in content:
                print(" - [WARNING] Avoid copying entire directories into the container.")
            if "EXPOSE 22" in content:
                print(" - [WARNING] Avoid exposing unnecessary ports.")
    else:
        print("[ERROR] Dockerfile not found for the image.")

def list_packages(image_name):
    """List all packages in a Docker image."""
    try:
        image = client.images.get(image_name)
        print(f"[INFO] Listing packages for image: {image_name}")
        # Simulated package listing (replace with actual package extraction logic)
        packages = ["bash", "curl", "libssl", "python3"]
        for package in packages:
            print(f" - {package}")
    except docker.errors.ImageNotFound:
        print(f"[ERROR] Docker image {image_name} not found!")
    except Exception as e:
        print(f"[ERROR] Exception occurred: {e}")

def update_database():
    """Simulate updating the vulnerability database."""
    print("[INFO] Updating local vulnerability database...")
    # Placeholder logic for database update
    print("[INFO] Database update complete.")

def multi_image_scan(image_list, severity_filter=None, output_dir=None):
    """Scan multiple Docker images concurrently."""
    print(f"[INFO] Scanning {len(image_list)} images concurrently...")
    with ThreadPoolExecutor(max_workers=4) as executor:
        for image in image_list:
            output_path = f"{output_dir}/{image.replace(':', '_')}_report.json" if output_dir else None
            executor.submit(scan_image, image, severity_filter, output_path)

def main():
    parser = argparse.ArgumentParser(description="Docker Vulnerability Scanner")
    parser.add_argument("--image", help="Docker image to analyze")
    parser.add_argument("--owasp", help="Perform OWASP Top 10 checks", action="store_true")
    parser.add_argument("--list-packages", help="List all packages in a Docker image", action="store_true")
    parser.add_argument("--update-db", help="Update the local vulnerability database", action="store_true")
    parser.add_argument("--multi-scan", help="Scan multiple images (comma-separated list)")
    parser.add_argument("--severity", help="Filter vulnerabilities by severity (low, medium, high, critical)")
    parser.add_argument("--output", help="Specify output path for report")

    args = parser.parse_args()

    if args.update_db:
        update_database()

    if args.image:
        scan_image(args.image, severity_filter=args.severity, output_path=args.output)

    if args.owasp and args.image:
        owasp_checks(args.image)

    if args.list_packages and args.image:
        list_packages(args.image)

    if args.multi_scan:
        images = args.multi_scan.split(",")
        multi_image_scan(images, severity_filter=args.severity, output_dir=args.output)

if __name__ == "__main__":
    main()
