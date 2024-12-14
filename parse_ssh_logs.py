# Import the re module for regular expression operations
import re


def parse_ssh_logs(file_path):
    """
    Parse SSH logs to detect brute-force login attempts.

    Parameters:
        file_path (str): Path to the SSH log file.

    Returns:
        dict: A dictionary containing IP addresses and their failed login attempt counts
              that meet or exceed the brute-force threshold.
    """

    # Define regex pattern to identify failed login attempts
    failed_login_pattern = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"

    # Define brute-force threshold (number of failed attempts)
    brute_force_threshold = 5

    # Dictionary to store failed login attempts per IP
    ip_failed_attempts = {}

    # Attempt to open and read the log file
    try:
        with open(file_path, "r") as log_file:
            for line in log_file:
                # Search for failed login pattern in each line
                failed_match = re.search(failed_login_pattern, line)
                if failed_match:
                    # Extract the IP address from the matched line
                    ip = failed_match.group(1)
                    # Update the count of failed attempts for this IP
                    ip_failed_attempts[ip] = ip_failed_attempts.get(ip, 0) + 1

        # Identify IPs that meet or exceed the brute-force threshold
        brute_force_ips = {
            ip: count
            for ip, count in ip_failed_attempts.items()
            if count >= brute_force_threshold
        }

        return brute_force_ips  # Return the detected brute-force IPs

    except FileNotFoundError:
        print(f"Error: The file at '{file_path}' was not found.")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}


# Main script to run the function
if __name__ == "__main__":
    # Prompt the user for the SSH log file path
    log_file_path = input("Enter the path to the SSH log file: ")

    # Call the function to parse logs and detect brute-force attempts
    brute_force_ips = parse_ssh_logs(log_file_path)

    # Display results to the user
    if brute_force_ips:
        print("Potential brute-force attack detected from the following IP(s):")
        for ip, count in brute_force_ips.items():
            print(f"IP: {ip}, Failed Attempts: {count}")
    else:
        print("No brute-force attempts detected.")
