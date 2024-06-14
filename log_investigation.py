"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""
import log_analysis_lib
import re
import os
import pandas as pd

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()
    

    # Per step 9, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report()

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value)

    Returns:
        dict: Dictionary of destination port number counts
    """
    # TODO: Complete function body per step 7
    dpt_logs = log_analysis_lib.filter_log_by_regex(log_path, r'DPT=(.*?) ')[1]
    dpt_tally = {}
    for dpt in dpt_logs:
        dpt_tally[dpt[0]] = dpt_tally.get(dpt[0], 0) + 1
    return dpt_tally

def generate_port_traffic_report(port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    # TODO: Complete function body per step 8
    # Get data from records that contain the specified destination port
    captured_data = []
    
    with open(log_path,'r') as file:
        
        for record in file:
            pattern = f'.*DPT={port_number}.*'
            search_flags= re.IGNORECASE
            match = re.search(pattern,record,search_flags)
            if match:
                match1 = re.search(r'([A-Za-z].*[0-9][0-9]) ([0-9][0-9].[0-9][0-9].[0-9][0-9]).*SRC=(.*?) DST=(.*?) .*SPT=(.*?) DPT=(.*?) ',record, search_flags)
                captured_data.append(match1.groups())
                file_path = os.path.dirname(os.path.abspath('log_investigation.py'))
                file_name = f'destination_port_{port_number}_report.csv'
                proper_file_path = os.path.join(file_path,file_name)
                df = pd.DataFrame(captured_data,columns=('Date','time','Source IP address','Destination IP address','Source port','Destination port'))
                df.to_csv(proper_file_path, index=False)
    # Generate the CSV report

    return

def generate_invalid_user_report():
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    # TODO: Complete function body per step 10
    # Get data from records that show attempted invalid user login
    # Generate the CSV report
    captured_data = []
    with open(log_path,'r') as file:
        for record in file:
            
            pattern = '.*Invalid user.*'
            search_flags = re.IGNORECASE
            match = re.search(pattern,record,search_flags)
            if match:
                match1 = re.search(r'([A-Za-z].*[0-9][0-9]) ([0-9][0-9].[0-9][0-9].[0-9][0-9]).*Invalid user ([A-Za-z]*) .* ([0-9]+.[0-9]+.[0-9]+.[0-9]+)',record)
                captured_data.append(match1.groups())
                file_path = os.path.dirname(os.path.abspath('log_investigation.py'))
                file_name = 'invalid_users.csv'
                proper_file_path = os.path.join(file_path,file_name)
                df = pd.DataFrame(captured_data,columns=('Date','time','Username','IP Adrress'))
                df.to_csv(proper_file_path, index=False)
    return

def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # TODO: Complete function body per step 11
    # Get all records that have the specified source IP address
    # Save all records to a plain text .log file
    all_info_src_address = log_analysis_lib.filter_log_by_regex(log_path, r'.*SRC=220.195.35.40.*')[0]
    #print(all_info_src_address)
    file_path = os.path.dirname(os.path.abspath('log_investigation.py'))
    new = re.sub(r'\.' , '_' , ip_address)
    file_name = f'source_ip_{new}.txt'
    proper_file_path = os.path.join(file_path,file_name)
    o_file = open(proper_file_path,"a")
    for record1 in all_info_src_address:
        o_file.write(record1)
        o_file.write('\n')
    o_file.close()    
    return

if __name__ == '__main__':
    main()