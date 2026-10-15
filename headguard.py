
import requests
from urllib.parse import urlparse
from datetime import datetime

SECURITY_HEADERS = {
    "Content-Security-Policy":
        "Helps control which sources a page can load content from.",

    "Strict-Transport-Security":
        "Tells browsers to use HTTPS for future connections.",

    "X-Content-Type-Options":
        "Helps prevent MIME-type sniffing when set to nosniff.",

    "X-Frame-Options":
        "Helps protect against clickjacking when configured correctly.",

    "Referrer-Policy":
        "Controls how much referrer information the browser sends.",

    "Permissions-Policy":
        "Controls access to supported browser features."
}


def check_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    return url


def scan_headers(url):
    check_url(url)

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "HeaderGuard/1.0"}
        )
    except requests.RequestException as error:
        print(f"[ERROR] Request failed: {error}")
        return

    report = []

    def add_line(line=""):
        print(line)
        report.append(line)

    add_line("\n=== HeaderGuard Security Report ===")
    add_line(f"Scan time:     {datetime.now().astimezone().isoformat(timespec='seconds')}")
    add_line(f"Requested URL: {url}")
    add_line(f"Final URL:     {response.url}")
    add_line(f"HTTP Status:   {response.status_code}")
    add_line(f"HTTPS:         {response.url.startswith('https://')}")
    add_line("\n--- Security Header Checks ---")

    present_count = 0
    missing_count = 0
    not_checked_count = 0

    headers = {
        name.lower(): value
        for name, value in response.headers.items()
    }

    for header, explanation in SECURITY_HEADERS.items():
        value = headers.get(header.lower())

        if (
            header == "Strict-Transport-Security"
            and not response.url.startswith("https://")
        ):
            add_line(f"[INFO] {header}: Check requires HTTPS.")
            not_checked_count += 1

        elif value:
            add_line(f"[PRESENT] {header}: {value}")
            present_count += 1

        else:
            add_line(f"[MISSING] {header}")
            add_line(f"          Why it matters: {explanation}")
            missing_count += 1

    total_checked = present_count + missing_count
    score = (
        present_count / total_checked * 100
        if total_checked
        else 0
    )

    add_line("\n--- Security Header Summary ---")
    add_line(f"Headers present: {present_count}")
    add_line(f"Headers missing: {missing_count}")
    add_line(f"Headers not checked: {not_checked_count}")
    add_line(f"Headers checked: {total_checked}")
    add_line(f"Header presence score: {score:.1f}%")

    filename = "security_report.txt"

    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write("\n".join(report) + "\n")

        print(f"\n[+] Report saved to: {filename}")

    except OSError as error:
        print(f"\n[ERROR] Could not save report: {error}")

    response.close()


if __name__ == "__main__":
    target = input("Enter the website URL to check: ").strip()

    try:
        scan_headers(target)
    except ValueError as error:
        print(f"[ERROR] {error}")
