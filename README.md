<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# write a README.md file for this Cybersecurity with Python — Part4: Detecting Threats in Apache Logs

[](https://medium.com/@vaibhavitilak17?source=post_page---byline--2090992e8f71---------------------------------------)
[Vaibhavi Tilak](https://medium.com/@vaibhavitilak17?source=post_page---byline--2090992e8f71---------------------------------------)
4 min read
·
May 10, 2025
[](https://medium.com/plans?dimension=post_audio_button&postId=2090992e8f71&source=upgrade_membership---post_audio_button-----------------------------------------)
In the evolving landscape of cybersecurity, visibility into your systems is everything. Among the most valuable but underutilized resources in a defender’s toolkit are web server access logs. In this article, we’ll explore how to use Python to analyze Apache access logs to detect early signs of malicious activity such as scanning, brute-force attempts, and suspicious traffic bursts.
Why Apache Logs?
Apache HTTP Server logs every request made to your web server — including IP addresses, timestamps, requested URLs, response codes, and user agents. While these logs don’t explicitly state “this was a brute-force attack,” they contain all the clues needed to hunt for threats.
83.149.9.216 — — [17/May/2015:10:05:03 +0000] “GET /index.html HTTP/1.1” 200 1234
Repeated requests like this in short bursts from the same IP can indicate:
Credential brute-force attempts
URL fuzzing / scanning
Malware probes
Logic Behind Threat Detection
In this article, we focus on detecting IP addresses that make more than 10 requests within a one-minute window — a common indicator of automated tools like scanners or brute-force scripts.
Step-by-Step Breakdown
Load the log file: Read the Apache access log line by line.
Extract IP and Timestamp: Use regex to pull out the client IP and the time the request was made.
Group requests by IP: Store all timestamps per IP.
Detect rapid-fire requests:
Sort timestamps for each IP.
Check if any 10 requests fall within a 60-second window.
If so, flag that IP as suspicious.
import re
from datetime import datetime, timedelta
from collections import defaultdict

# 1. Load logs from file

def load_logs(file_path):
with open(file_path, 'r') as f:
return f.readlines()

# 2. Parse IPs and timestamps

def parse_logs(log_lines):

    pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<datetime>[^\]]+)\]')
    ip_timestamps = defaultdict(list)
    
    for line in log_lines:
        match = pattern.search(line)
        if match:
            ip = match.group('ip')
            dt_str = match.group('datetime').split()[0]  # remove timezone
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

# 4. Main

if __name__ == "__main__":
logs = load_logs("apache_logs.txt")
ip_data = parse_logs(logs)
detect_suspicious_ips(ip_data)
Press enter or click to view image in full size
Here’s what our Python script does:
if times[i+9] - times[i] <= timedelta(minutes=1):
This line checks if 10 consecutive requests (i to i+9) happened within 60 seconds. If yes, we assume it's non-human behavior, likely a bot or script, and log a warning.
The result:
⚠️  IP 83.149.9.216 made 10+ requests between 2015-05-17 10:05:03 and 2015-05-17 10:05:57
Once a SOC analyst identifies a suspicious IP, they should quickly gather context, check threat intelligence feeds, and review related logs for unusual activity. If a threat is detected, the analyst isolates affected systems, blocks the IP, and follows incident response protocols to mitigate the risk. Post-incident, they conduct a root cause analysis, improve defenses, and document the incident for compliance and future prevention.
Note: For testing and demonstration purposes, I used publicly available Apache log samples from this GitHub repository: [https://github.com/elastic/examples/tree/master/Common%20Data%20Formats/apache_logs](https://github.com/elastic/examples/tree/master/Common%20Data%20Formats/apache_logs)
This dataset provides real-world-like log entries, making it an excellent resource for learning and experimenting with log analysis techniques.
Let’s understand Sample Log Entry:
83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"IP Address (83.149.9.216)
IP Address (83.149.9.216)- This is the client IP address. It shows where the request originated from, i.e., the user’s machine or device.
2. User Identity (-)
This field is usually the authenticated user (if available). In this case, it’s -, meaning there was no authenticated user for this request.
3. Authenticated User (-)
This is another placeholder -. If the user was authenticated, it would show the username. Since it's -, it means no specific user was authenticated.
4. Timestamp ([17/May/2015:10:05:03 +0000]) — The timestamp indicates when the request was made.
Format: [day/month/year:hour:minute:second timezone]
+0000 represents the timezone (UTC in this case).
5. Request (“GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1”)
This shows the HTTP request made by the client.
GET is the HTTP method used (asking the server to fetch a resource).
/presentations/logstash-monitorama-2013/images/kibana-search.png is the requested resource.
HTTP/1.1 is the HTTP version used.
6. Status Code (200)- The HTTP response code200 indicates a successful request where the server returned the requested resource.
7. Response Size (203023)
This is the size of the response in bytes. It tells us how much data was sent back to the client.
8. Referrer (“[http://semicomplete.com/presentations/logstash-monitorama-2013/](http://semicomplete.com/presentations/logstash-monitorama-2013/)")
The Referrer indicates the webpage the client was on before making this request.
In this case, the client came from a page on semicomplete.com related to the Logstash presentation.
9. User-Agent (“Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36”)
The User-Agent string identifies the client software making the request.
This example indicates the client is using a Macintosh computer with Chrome browser on OS X 10.9.1.
In this article, we used Python to analyze Apache logs and detect potential brute-force attacks. With simple code and real log data from GitHub, we showed how easily you can start threat hunting using basic scripting. This is a great first step into automated log analysis — and there’s much more ahead as we explore deeper security use cases in upcoming articles.
[Cybersecurity](https://medium.com/tag/cybersecurity?source=post_page-----2090992e8f71---------------------------------------)
[Apache Logs](https://medium.com/tag/apache-logs?source=post_page-----2090992e8f71---------------------------------------)
[Bruteforce Attack](https://medium.com/tag/bruteforce-attack?source=post_page-----2090992e8f71---------------------------------------)
[Detection](https://medium.com/tag/detection?source=post_page-----2090992e8f71---------------------------------------)
[Log Analysis](https://medium.com/tag/log-analysis?source=post_page-----2090992e8f71---------------------------------------)

```markdown
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

---

## Next Steps

Explore deeper security analytics with Python, including:

- Parsing and analyzing other log formats  
- Advanced pattern detection (e.g., failed login attempts)  
- Integration with SIEM tools for automated alerting  

---

*Happy Threat Hunting!*  
*— Vai (Vaibhavi Tilak)*

---

![Apache Log Example](https://miro.medium.com/max/1400/1*vN5pr_g2k96xqYpX6d_mpw.png)

*Example Apache log entry with timestamp and client IP extraction*

```

This README.md is ready for GitHub upload and clearly documents your Part 4 project on detecting threats in Apache logs with Python. Let me know if you want me to help add more details or create complementary files!

<div style="text-align: center">⁂</div>

[^1]: https://medium.com/@vaibhavitilak17

[^2]: https://medium.com/@

