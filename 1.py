import pandas as pd
import re

def detect_sql_injection(info):
    # List of common SQL injection commands and patterns
    sql_injection_commands = [
        "SELECT",
        "UNION",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "EXEC",
        "TRUNCATE",
        "OR 1=1",
        "OR '1'='1'",
        "--",
        ";--",
        "/*",
        "*/",
        "@@",
        "CHAR",
        "WAITFOR",
        "BENCHMARK"
    ]
    
    info_upper = info.upper()
    for command in sql_injection_commands:
        if command.upper() in info_upper:
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
        

        print()

        for _  in list(map(lambda x: x[-1] ,  sql_injection_attempts)):
            print(_ + "\n\n")

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
