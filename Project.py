import re
import csv
from collections import defaultdict, Counter

def parse_log_file(log_file_path):
    """
    Parses the log file and extracts relevant information.
    Returns IP requests, endpoint accesses, and failed login attempts.
    """
    requests_per_ip = Counter()
    endpoint_accesses = Counter()
    failed_logins = defaultdict(int)
    failed_login_threshold = 10

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                # Extract IP address
                ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip_address = ip_match.group(1)
                    requests_per_ip[ip_address] += 1

                # Extract endpoint
                endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/1\.\d"', line)
                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    endpoint_accesses[endpoint] += 1

                # Detect failed login attempts (status 401)
                if '401' in line or 'Invalid credentials' in line:
                    if ip_match:  # Ensure we have the IP address
                        failed_logins[ip_address] += 1

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return requests_per_ip, endpoint_accesses, failed_logins, failed_login_threshold

    return requests_per_ip, endpoint_accesses, failed_logins, failed_login_threshold

def find_most_accessed_endpoint(endpoint_accesses):
    """
    Finds the most accessed endpoint.
    """
    if endpoint_accesses:
        most_accessed = endpoint_accesses.most_common(1)[0]
        return most_accessed  # Returns (endpoint, count)
    return None, 0

def save_results_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity, output_file='log_analysis_results.csv'):
    """
    Saves the results to a CSV file.
    """
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP Address
        writer.writerow(["IP Address", "Request Count"])
        if requests_per_ip:
            for ip, count in requests_per_ip.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(["No data available"])

        writer.writerow([])  # Add an empty row for separation

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        if most_accessed_endpoint[0]:
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        else:
            writer.writerow(["No data available"])

        writer.writerow([])  # Add an empty row for separation

        # Write Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        if suspicious_activity:
            for ip, count in suspicious_activity.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(["No data available"])

    print(f"Results saved to {output_file}")

def main():
    """
    Main function to run the log analysis script.
    """
    # Path to the log file
    log_file_path = r"C:\Users\Jay Dake\Desktop\Fuel\sample.log.txt"

    # Parse the log file
    print("Parsing log file...")
    requests_per_ip, endpoint_accesses, failed_logins, failed_login_threshold = parse_log_file(log_file_path)

    # Find most accessed endpoint
    most_accessed_endpoint = find_most_accessed_endpoint(endpoint_accesses)

    # Filter suspicious activity
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > failed_login_threshold}

    # Save results to CSV
    save_results_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity)

    # Display summary in terminal
    print("\nRequests per IP Address:")
    if requests_per_ip:
        for ip, count in requests_per_ip.most_common():
            print(f"{ip} -> {count} requests")
    else:
        print("No data found for IP requests.")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint[0]:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        print("No data found for endpoint accesses.")

    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip} -> {count} failed login attempts")
    else:
        print("No suspicious activity detected.")

if __name__ == "__main__":
    main()
