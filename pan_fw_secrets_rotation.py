import csv
import requests
import random
import string
from getpass import getpass
import hashlib
import subprocess

def generate_api_key(firewall_ip, username, password):
    url = f"https://{firewall_ip}/api/?type=keygen&user={username}&password={password}"
    response = requests.get(url, verify=False)
    if response.status_code == 200:
        key = response.text.split("<key>")[1].split("</key>")[0]
        return key
    else:
        raise Exception("Failed to generate API key")

def generate_phash(password, salt):
    command = f'openssl passwd -5 -salt {salt} {password}'
    output = subprocess.check_output(command, shell=True, universal_newlines=True)
    phash = output.strip()
    return phash

def change_password(firewall_ip, api_key, username, new_password):
    phash = generate_phash(new_password, "sampleSALT")  # Replace "sampleSALT" with your salt value
    url = f"https://{firewall_ip}/api/?type=config&action=set&key={api_key}&xpath=/config/mgt-config/users/entry[@name='{username}']/phash&element=<phash>{phash}</phash>"
    response = requests.get(url, verify=False)
    if response.status_code == 200 and "<msg>command succeeded</msg>" in response.text:
        return True
    else:
        return False

# Prompt user for password requirements
username = "admin"
password = getpass(f"Enter the password for {username}: ")
length = int(input("Enter the desired length of the password: "))
special_chars = input("Enter the special characters to include (leave empty for no special characters): ")

# Generate a random password
characters = string.ascii_letters + string.digits + special_chars
new_password = ''.join(random.choice(characters) for _ in range(length))

# Replace with the path to your CSV inventory file
inventory_file = "PAN_INVENTORY.csv"

password_changes = []

with open(inventory_file, 'r') as file:
    reader = csv.DictReader(file)
    for row in reader:
        firewall_ip = row['FIREWALL_IP']

        # Generate API key with the new password
        new_api_key = generate_api_key(firewall_ip, username, new_password)

        # Change password
        success = change_password(firewall_ip, new_api_key, username, new_password)

        # Attempt to log back into the firewall with the new password
        login_url = f"https://{firewall_ip}/api/?type=op&cmd=<show><system><info></info></system></show>&key={new_api_key}"
        response = requests.get(login_url, verify=False)

        if success and response.status_code == 200:
            password_changes.append((firewall_ip, True))
            print(f"Password change successful for {firewall_ip}")
        else:
            password_changes.append((firewall_ip, False))
            print(f"Password change failed for {firewall_ip}")

# Print password changes and new password
print("\nPassword Changes:")
for firewall, success in password_changes:
    print(f"{firewall}: {'Success' if success else 'Failed'}")

print(f"\nNew Password: {new_password}")
