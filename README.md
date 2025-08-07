
# Cybersecurity with Python — Part 4: Detecting Threats in Apache Logs

In the evolving landscape of cybersecurity, visibility into your systems is everything. One of the most valuable and often underutilized resources in a defender’s toolkit is the web server access log. This project demonstrates how to use Python to analyze Apache access logs to detect early signs of malicious activity such as scanning, brute-force attempts, and suspicious traffic bursts.

---

## Why Apache Logs?

Apache HTTP Server logs every request made to your web server — including IP addresses, timestamps, requested URLs, response codes, and user agents. These logs contain all the clues needed to hunt for threats like credential brute-force attempts, URL fuzzing/scanning, or malware probes.

Example Apache log entry:

```

83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /index.html HTTP/1.1" 200 1234

```

---

## Threat Detection Logic

This project focuses on detecting IP addresses that make **more than 10 requests within a one-minute window** — a common indicator of automated scanning or brute-force attack scripts.

---

## How It Works: Step-by-Step Breakdown

1. **Load the log file:** Read the Apache access log line by line.  
2. **Extract IP and timestamp:** Use a regex pattern to extract the client IP address and the time of each request.  
3. **Group requests by IP:** Store all timestamps for each IP address.  
4. **Detect rapid requests:**  
   - Sort timestamps for each IP.  
   - Check if any consecutive 10 requests happen within 60 seconds.  
   - Flag such IPs as suspicious.

---

## Python Script

```

import re
from datetime import datetime, timedelta
from collections import defaultdict

# 1. Load logs from file

def load_logs(file_path):
with open(file_path, 'r') as f:
return f.readlines()

# 2. Parse IPs and timestamps

def parse_logs(log_lines):

    pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?$(?P<datetime>[^$]+)$$')
    ip_timestamps = defaultdict(list)
    
    for line in log_lines:
        match = pattern.search(line)
        if match:
            ip = match.group('ip')
            dt_str = match.group('datetime').split()  # remove timezone
            dt_obj = datetime.strptime(dt_str, "%d/%b/%Y:%H:%M:%S")
            ip_timestamps[ip].append(dt_obj)
    
    return ip_timestamps
    
# 3. Detect IPs with 10+ requests in 1 minute

def detect_suspicious_ips(ip_timestamps):
print("\n🔍 Potential scanning or brute-force behavior detected:\n")
for ip, times in ip_timestamps.items():
times.sort()
for i in range(len(times) - 9):
if times[i+9] - times[i] <= timedelta(minutes=1):
print(f"⚠️  IP {ip} made 10+ requests between {times[i]} and {times[i+9]}")
break

# 4. Main execution

if __name__ == "__main__":
logs = load_logs("apache_logs.txt")
ip_data = parse_logs(logs)
detect_suspicious_ips(ip_data)

```

---

## Explanation

- The regex extracts IP addresses and timestamps from each log line.
- Timestamps are parsed into Python `datetime` objects for accurate time comparison.
- The script checks if any IP has made **10 or more requests within any 60-second window**.
- Such behavior is flagged as suspicious, indicating possible brute-force or scanning activity.

---

## Sample Output

```

⚠️  IP 83.149.9.216 made 10+ requests between 2015-05-17 10:05:03 and 2015-05-17 10:05:57

```

---

## Understanding the Apache Log Entry

A sample log line:

```

83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /resource/path HTTP/1.1" 200 1234 "http://referrer" "User-Agent string"

```

- **IP Address:** The client’s IP (e.g., 83.149.9.216)  
- **User Identity and Authenticated User:** Often reported as `-` if not applicable  
- **Timestamp:** Date and time of the request with timezone  
- **Request:** HTTP method, resource path, and protocol  
- **Status Code:** Server response code (e.g., 200)  
- **Response Size:** Size of server response in bytes  
- **Referrer:** The URL of the referring webpage  
- **User-Agent:** Client software identification string

---

## Usage Notes

- Use publicly available sample logs to test, like [Elastic’s Apache logs dataset](https://github.com/elastic/examples/tree/master/Common%20Data%20Formats/apache_logs).  
- Detect suspicious IPs early and augment with threat intelligence checks.  
- Follow incident response protocols on confirmed threats.

---

## Conclusion

This Python-based approach provides a straightforward and effective way to detect suspicious behavior in Apache access logs, helping defenders take early action against automated attacks like brute-force scans and fuzzing.

*Happy Threat Hunting!*  
*— Vai (Vaibhavi Tilak)*

---


