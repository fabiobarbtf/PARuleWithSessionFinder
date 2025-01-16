# Author: Fábio Barbosa
# Date: 16/01/2025
# Description: Script to collect rules with active sessions in Palo Alto Networks firewall, using the Netmiko library for SSH connection.
#              The script connects to the firewall, collects active sessions, and saves the rules with active sessions in .txt and .csv files.
# Requires installation via pip of the libraries: Netmiko and Pandas.

# Import Libraries
from netmiko import ConnectHandler
import pandas as pd
from io import StringIO
import getpass

# Global Variables
BANNER = r"""
 ____       _            _    _ _                                  
|  _ \ __ _| | ___      / \  | | |_ ___                            
| |_) / _` | |/ _ \    / _ \ | | __/ _ \                           
|  __/ (_| | | (_) |  / ___ \| | || (_) |                          
|_|__ \__,_|_|\___/  /_/  _\_\_|\__\___/_   _                      
|  _ \ _   _| | ___  ___  \ \      / (_) |_| |__                   
| |_) | | | | |/ _ \/ __|  \ \ /\ / /| | __| '_ \                  
|  _ <| |_| | |  __/\__ \   \ V  V / | | |_| | | |                 
|_|_\_\\__,_|_|\___||___/    \_/\_/  |_|\__|_| |_|     _           
/ ___|  ___  ___ ___(_) ___  _ __   |  ___(_)_ __   __| | ___ _ __ 
\___ \ / _ \/ __/ __| |/ _ \| '_ \  | |_  | | '_ \ / _` |/ _ \ '__|
 ___) |  __/\__ \__ \ | (_) | | | | |  _| | | | | | (_| |  __/ |   
|____/ \___||___/___/_|\___/|_| |_| |_|   |_|_| |_|\__,_|\___|_|   
"""
TERMS_TO_EXCLUDE = ['Vsys', 'vsys1', '--------------------------------------------------------------------------------']
PREFIX_TEXT = 'show session id '
SUFFIX_TEXT = ' | match rule'
TERMS_TO_EXCLUDE_RULES = ['QoS']

# User Input Function
def get_user_input(prompt):
    return input(prompt)

# GetPassword Function
def get_password_input(prompt):
    return getpass.getpass(prompt)

# Firewall Connection Function
def connect_to_firewall(mgmt, user, password):
    firewall = {
        "device_type": "paloalto_panos",
        "host": mgmt,
        "username": user,
        "password": password
    }
    return ConnectHandler(**firewall)

# Output Processing Function
def process_output(output):
    lines = output.splitlines()[3:]
    processed_lines = [line.split(' ', 1)[0] for line in lines]
    return "\n".join(processed_lines)

# DataFrame Filter Function
def filter_dataframe(df, terms):
    mask = df.apply(lambda col: col.str.contains('|'.join(terms), case=False, na=False))
    return df[~mask.any(axis=1)]

# Add Prefix and Suffix Function
def add_prefix_suffix(df, prefix, suffix):
    return df.apply(lambda row: prefix + ' '.join(row.astype(str)) + suffix, axis=1)

# Save to File Function
def save_to_file(filename, data):
    with open(filename, 'w') as file:
        file.writelines(data)

# Main Function
def main():
    # Banner Function Call
    print(BANNER)
    
    # Input Functions Call
    mgmt = get_user_input("Please enter the firewall IP!\nManagement IP: ")
    print("")
    user = get_user_input("Enter the login username!\nUser: ")
    print("")
    password = get_password_input("Enter the login password!\nPassword: ")
    print("")
    
    # Try/Except Block
    try:
        # Firewall Connection Call
        connection = connect_to_firewall(mgmt, user, password)
        print("Connection Successful! Continuing the script, please wait...")
        print("")
        
        # CLI Configuration Commands and Session Display via SSH
        output = connection.send_command("set cli config-output-formar set", expect_string=r">")
        output = connection.send_command("set cli pager off", expect_string=r">")
        output = connection.send_command("show session all", expect_string=r">")
        
        # Output Processing
        processed_text = process_output(output)
        df = pd.read_csv(StringIO(processed_text))
        df_filtered = filter_dataframe(df, TERMS_TO_EXCLUDE)
        df_final = add_prefix_suffix(df_filtered, PREFIX_TEXT, SUFFIX_TEXT)
        
        # Save Show Session Commands to File
        df_final.to_csv('showcommands.txt', sep=' ', index=False, header=True)
        print("Show commands collected and saved in .txt file! Continuing...")
        print("")
        
        # Read Commands File with Data Processing
        with open('showcommands.txt', 'r') as file:
            lines = file.readlines()[1:]
        lines = [line.replace('"', '') for line in lines]
        save_to_file('showcommands.txt', lines)
        
        # Read Show Session Commands File
        with open('showcommands.txt', 'r') as file:
            commands = file.readlines()
        
        # Loop to Collect Session Information
        print("Collecting rules with active sessions, please wait...")
        print("")
        str_rules = "Rules With Active Sessions"
        for command in commands:
            output2 = connection.send_command(command, expect_string=r">")
            str_rules += output2
        
        # Output Processing
        df_rules = pd.read_csv(StringIO(str_rules))
        df_rules_filtered = filter_dataframe(df_rules, TERMS_TO_EXCLUDE_RULES)
        df_rules_filtered.iloc[:, 0] = df_rules_filtered.iloc[:, 0].str.replace(r'^.*?:', ':', regex=True)
        df_rules_filtered = df_rules_filtered.apply(lambda col: col.str.replace(':', '', regex=False) if col.dtype == 'object' else col)
        df_rules_filtered = df_rules_filtered.drop_duplicates(keep='last')
        df_rules_filtered = df_rules_filtered.apply(lambda col: col.str.replace(r'\(vsys1\)', '', regex=True) if col.dtype == 'object' else col)
        
        # Save Rules with Active Sessions to File
        df_rules_filtered.to_csv('active_sessions.csv', index=False)
        df_rules_filtered.to_csv('active_sessions.txt', sep='\t', index=False)
        
        # Completion Message
        print("Script completed!")
        print("The names of the rules with active sessions have been saved in .txt and .csv files")
    
    # Exception Block (Error Presentation)
    except Exception as e:
        print(f"Error: {e}")
    
    # Input to Keep Window Open
    input()

# Main Function Call
if __name__ == "__main__":
    main()