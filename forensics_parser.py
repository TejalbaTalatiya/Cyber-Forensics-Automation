import re
import pandas as pd

def parse_security_logs(log_data_text):
    """
    Uses Regex pattern matching to extract structured fields 
    from unstructured system log streams.
    """
    timestamp_pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    parsed_records = []
    
    for line in log_data_text.strip().split('\n'):
        timestamp = re.search(timestamp_pattern, line)
        ip_address = re.search(ip_pattern, line)
        
        if timestamp and ip_address:
            log_level = "UNKNOWN"
            if "INFO" in line: log_level = "INFO"
            elif "WARN" in line: log_level = "WARN"
            elif "ERROR" in line: log_level = "ERROR"
            
            parsed_records.append({
                "Timestamp": timestamp.group(0),
                "IP_Address": ip_address.group(0),
                "Log_Level": log_level,
                "Raw_Payload": line.strip()
            })
            
    df = pd.DataFrame(parsed_records)
    return df

if __name__ == "__main__":
    sample_logs = """
    2026-06-18 10:14:22 [INFO] Connection established from node 192.168.1.45 safely.
    2026-06-18 10:15:01 [WARN] Unauthorized access attempt detected from 10.0.0.12.
    2026-06-18 10:16:12 [ERROR] Fatal system breach protocol initiated from 172.16.254.1.
    """
    structured_df = parse_security_logs(sample_logs)
    print("[Success] Extracted Forensic DataFrame:")
    print(structured_df.to_string())
