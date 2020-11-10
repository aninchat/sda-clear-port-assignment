"""
Author: Aninda Chatterjee
Input:
    DNAC credentials (username/password and IP address)
    Excel sheet with host onboarding information in .csv file format with specific format as below:
        Row 0 - Device name exactly as it shows in DNAC inventory (example - Edge1.cisco.com)
        Row 1 - Complete interface name (example - GigabitEthernet1/0/15)
Usage: This script is designed to take a .csv file as input and clear assignment of all interfaces listed in the 
file.
"""
import rich
import csv
import requests
import warnings
import getpass
import json
from requests.auth import HTTPBasicAuth

class MyError(Exception):
    """Custom base class for exceptions"""
    pass

class AuthenticationError(MyError):
    """To be raised when authentication failure occurs"""
    pass

def get_dnac_auth_token(dnac_ip_address, dnac_user, dnac_pass):

    # partial URL defined to concatenate later

    url = '/api/system/v1/auth/token'

    # get DNAC IP address and login details
    # commented out for now - a better approach is to
    # source this in the main function and then pass
    # it into this function

    #dnac_ip_address = input("Enter DNAC IP address: ")
    #dnac_user = input("Enter username for DNAC login: ")
    #dnac_pass = input("Enter password for DNAC login: ")

    # concatenate the DNAC IP address obtained from user
    # with the full string to form the complete URL needed to
    # obtain the token

    full_url = 'https://' + dnac_ip_address + url

    # the post request will throw a warning because certification
    # validation is being disabled with verify=False
    # this displays the warning to the user, so we are filtering it

    warnings.filterwarnings("ignore")

    # post request to retreive token in json format and then store it
    # as a string in a variable called token. Return this variable

    response = requests.post(full_url, auth=HTTPBasicAuth(dnac_user,dnac_pass), headers={"Content-Type": "application/json"}, verify=False)
    token = response.json()["Token"]
    return token

def host_clear_assignment(token, dnac_ip_address, fabric_devices, file_path):

    # first, load csv file which contains host information

    # note the explicit encoding added when opening the file 
    # without this, the first entry in the first row is prepended
    # with the encoding format

    try:
        with open(file_path, 'r', encoding='utf-8-sig') as host_onboarding_file:
            host_onboarding_reader = csv.reader(host_onboarding_file)

            # each row should be a unique assignment in the format of
            # row[0] = hostname
            # row[1] = interface

            for row in host_onboarding_reader:
                # for the device in each row, find the device IP first

                for device in fabric_devices:
                    if device['hostname'] == row[0].strip():
                        device_ip = device['managementIpAddress']

                # once device IP is known, this can be used to build the API
                # to clear host assignment

                # prepare the URL and then call the API

                try:
                    host_clear_assignment_url = "https://" + dnac_ip_address + '/dna/intent/api/v1/business/sda/hostonboarding/user-device?device-ip=' + device_ip + '&' + 'interfaceName=' + row[1].strip()
                except:
                    rich.print(f"[red]Device {row[0].strip()} not found")
                    continue

                host_clear_assignment_api_call = requests.delete(host_clear_assignment_url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, verify=False)
                try:
                    if host_clear_assignment_api_call.json()['status']:
                        if host_clear_assignment_api_call.json()['status'] == 'pending':
                            rich.print(f"[green]Device {row[0]}, interface {row[1]} is being cleared")
                        elif host_clear_assignment_api_call.json()['status'] == 'failed':
                            if host_clear_assignment_api_call.json()['description'] == 'Interface name provided in get request is not assigned to any device.':
                                rich.print(f"[red]Interface {row[1]} does not have any static port assigned and cannot be cleared")
                            else:
                                rich.print(f"[red]Interface name {row[1]} could not be found or cleared")
                except:
                    rich.print(f"[red]Device {row[0]}, interface {row[1]} could not be cleared. Error with API, possibly rate-limited")
    except:
        rich.print("[red]Could not open file")

def get_all_fabric_devices(token, dnac_ip_address):
    url = '/api/v1/network-device'
    full_url = 'https://' + dnac_ip_address + url
    warnings.filterwarnings("ignore")
    response = requests.get(full_url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, verify=False)

    # strip the response to include only the "response"
    # entry from the json dictionary

    stripped_response = response.json()["response"]
    return stripped_response

def main():
    # get DNAC IP address and login details

    dnac_ip_address = input("Enter DNAC IP address: ")
    dnac_user = input("Enter username for DNAC login: ")
    dnac_pass = getpass.getpass(prompt="Enter password for DNAC login: ")
    try:
        token  = get_dnac_auth_token(dnac_ip_address, dnac_user, dnac_pass)
    except:
        raise AuthenticationError("Authentication failure. Please check DNAC IP address and login credentials.")

    # get list of all fabric devices first

    fabric_devices = get_all_fabric_devices(token, dnac_ip_address)

    file_path = input("Please specify complete path (including file name) to the host onboarding excel sheet: ") 
    host_clear_assignment(token, dnac_ip_address, fabric_devices, file_path)

if __name__ == '__main__':
    main()    
