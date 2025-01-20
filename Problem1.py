'''
Question 1 [Qualifying Round] (100 points) (Duration 2hrs):

As a SOC (Security Operations Center) engineer at a leading cybersecurity firm, you are tasked with analyzing a .csv file derived from a .pcap file to extract key details about an SQL injection attack. This .csv file contains relevant traffic logs from the .pcap, includes multiple protocols and application information.

The input.csv file containing the following columns:
 - No.: Packet number.
 - Time: Packet capture timestamp.
 - Source: Source IP address.
 - Destination: Destination IP address.
 - Protocol: Protocol used (e.g., HTTP).
 - Length: Packet length.
 - Info: Packet details 
 
Your manager has assigned you the task of writing a Python program to automate the extraction of critical information. The program should produce a concise output that provides insights into the attack, including SQL injection payloads, and other significant details.

Your Python program should process the given .csv file and extract the following details:

1. Source IP Address: Identify the attacker's IP address (There will be only one single IP) that initiated the SQL injection attack. If no attacks are detected, print “NULL” as output. 
Output Format : 1A:-Source IP-;

2. Count of SQL Injection Attempts: Calculate and display the total number of SQL injection attempts made by the attacker. If no attacks are detected, print 0 as output	.	     
Output Format: 2A:-Total SQL Injection Attempts-;

3. Initial SQL Injection Attempt: Extract and display the request URI from the first SQL injection attempt made by the attacker, based on the earliest timestamp. The output should only include the URI path and parameters, excluding the request method (eg: GET/POST) and protocol information (eg: HTTP/1.1). If no SQL injection attempts are found, print "NULL" as output.    
Output Format: 3A:-First Payload-;

4. Final SQL Injection Attempt: Extract and display the request URI from the final or the last SQL injection attempt made by the attacker, based on the earliest timestamp. The output should only include the URI path and parameters, excluding the request method (eg: GET/POST) and protocol information (eg: HTTP/1.1). If no SQL injection attempts are found, print "NULL" as output.   
Output Format: 4A:-Last Payload-;
5. Payloads Using Formatting Symbols: Count the number of SQL injection attempts containing the formatting symbol (colon), which is often used to structure SQL queries. If no such payloads are found, print 0 as output.
Output Format: 5A:-Number of Payloads Containing formatting symbol-;

Output format:
Your program should display the results for each query on separate lines, with clear and concise labels:
1A:-value-;
2A:-value-;
3A:-value-;
4A:-value-;
5A:-value-;

Note:
 - A sample.csv file will be provided for code development and testing.
 - Following is a link to file1.csv : https://drive.google.com/file/d/1irJOorQcqSM9sEibEViKIbkZU6GVn2ze/view?usp=drive_link
 - You must follow the exact output format to receive full marks. Pay close attention to spacing and symbols as defined in the output format above.
 - During evaluation, a different .csv file will be used to test the program's adaptability. Avoid hardcoding values.
 - There are a total of five test cases (one visible and four invisible) to validate your answer. Each test case is worth 20 points, making a total of 100 points (5 × 20 = 100).

'''
import pandas as pd
import re

def detect_sql_injection(info):
    # A simple regex pattern to detect SQL injection attempts
    sql_injection_patterns = [
        r"(?i)' or '1'='1",  # Common SQL injection pattern
        r"(?i)' --",         # SQL comment pattern
        r"(?i)union select", # UNION SELECT pattern
        r"(?i)select.+from", # SELECT FROM pattern
        r"(?i)or 1=1",       # OR 1=1 pattern
        r"(?i)' or 1=1 --",  # Another common pattern
        r"(?i)';",           # Ending with a semi-colon
        r"(?i)\bupdate\b",   # UPDATE statement
        r"(?i)\bdelete\b",   # DELETE statement
        r"(?i)\binsert\b",   # INSERT statement
    ]
    for pattern in sql_injection_patterns:
        if re.search(pattern, info):
            return True
    return False

def extract_uri(info):
    # Extract URI path and parameters
    match = re.search(r'(GET|POST) (.+?) (HTTP|HTTPS)/[0-9.]+', info, re.IGNORECASE)
    if match:
        return match.group(2)
    return None

def main():
    # Load the CSV file
    file_path = input().strip()
    data = pd.read_csv(file_path)
    
    sql_injection_attempts = []
    
    for index, row in data.iterrows():
        if detect_sql_injection(row['Info']):
            uri = extract_uri(row['Info'])
            if uri:
                sql_injection_attempts.append((row['Time'], row['Source'], uri))
    
    if sql_injection_attempts:
        # Sort attempts by time
        sql_injection_attempts.sort()
        
        attacker_ip = sql_injection_attempts[0][1]
        first_payload = sql_injection_attempts[0][2]
        last_payload = sql_injection_attempts[-1][2]
        total_attempts = len(sql_injection_attempts)
        payloads_with_colon = sum(1 for attempt in sql_injection_attempts if ':' in attempt[2])
        
        print(f"1A:-{attacker_ip}-;")
        print(f"2A:-{total_attempts}-;")
        print(f"3A:-{first_payload}-;")
        print(f"4A:-{last_payload}-;")
        print(f"5A:-{payloads_with_colon}-;")
    else:
        print("1A:-NULL-;")
        print("2A:-0-;")
        print("3A:-NULL-;")
        print("4A:-NULL-;")
        print("5A:-0-;")

if __name__ == "__main__":
    main()
