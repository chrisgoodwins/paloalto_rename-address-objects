###############################################################################
#
# Script:       rename-addr-objects.py
#
# Author:       Chris Goodwin <chrisgoodwins@gmail.com>
#
# Description:  Checks for IP address matches between an address object list
#               (in csv format) provided by the user, and the set of address
#               objects on a firewall or Panorama device group. If there is a
#               match, then the PAN address object is renamed to the object
#               name in the user-provided list. The script takes the csv file
#               as input via command line argument.
#
# Usage:        rename-addr-objects.py <user-provided-list.csv>
#
# Requirements: requests
#
# Python:       Version 3
#
###############################################################################
###############################################################################


import getpass
import sys
import re
import time
from xml.etree import ElementTree as ET
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise ValueError('requests support not available, please install module')

###############################################################################
###############################################################################


# Prompts the user to enter an address, then checks it's validity
def getfwipfqdn():
    while True:
        fwipraw = input('\nPlease enter Panorama/firewall IP or FQDN: ')
        ipr = re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', fwipraw)
        fqdnr = re.match(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', fwipraw)
        if ipr:
            break
        elif fqdnr:
            break
        else:
            print('\nThere was something wrong with your entry. Please try again...\n')
    return fwipraw


# Prompts the user to enter a username and password
def getCreds():
    while True:
        username = input('Please enter your user name: ')
        usernamer = re.match(r'^[\w-]{3,24}$', username)
        if usernamer:
            password = getpass.getpass('Please enter your password: ')
            break
        else:
            print('\nThere was something wrong with your entry. Please try again...\n')
    return username, password


# Retrieves the user's api key
def getkey(fwip):
    while True:
        try:
            username, password = getCreds()
            keycall = f'https://{fwip}/api/?type=keygen&user={username}&password={password}'
            r = requests.get(keycall, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == 'success':
                apikey = tree.find('./result/key').text
                break
            else:
                print('\nYou have entered an incorrect username or password. Please try again...\n')
        except requests.exceptions.ConnectionError:
            print('\nThere was a problem connecting to the firewall. Please check the address and try again...\n')
            exit()
    return apikey


# Presents the user with a choice of device-groups
def getDG(fwip, mainkey):
    dgXmlUrl = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/device-group&key={mainkey}"
    r = requests.get(dgXmlUrl, verify=False)
    devTree = ET.fromstring(r.text)
    devTreeString = './/device-group/entry'
    dgList = []
    for entry in devTree.findall(devTreeString):
        dgList.append(entry.get('name'))
    while True:
        try:
            print('\n\nHere\'s a list of device groups found in Panorama...\n')
            i = 1
            for dgName in dgList:
                print(f'{i}) {dgName}')
                i += 1
            dgChoice = int(input('\nChoose a number for the device-group:\n\nAnswer is: '))
            print('\n')
            time.sleep(1)
            reportDG = dgList[dgChoice - 1]
            break
        except:
            print("\n\nThat's not a number in the list, try again...\n")
            time.sleep(1)
    return reportDG


# Determines whether the device is Panorama or firewall
def getDevType(fwip, mainkey):
    devURL = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/device-group&key={mainkey}"
    r = requests.get(devURL, verify=False)
    devTree = ET.fromstring(r.text)
    if devTree.find('.//device-group/entry') is None:
        devType = 'fw'
        print('\n\n...Auto-detected device type to be a firewall...\n\n')
    else:
        devType = 'pano'
        print('\n\n...Auto-detected device type to be Panorama...\n\n')
    time.sleep(1)
    return devType


# Returns a list of address objects from firewall or Panorama DG
def getAddressObjects(fwip, mainkey, dg):
    if dg is None:
        devURL = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/vsys/entry/address&key={mainkey}"
        r = requests.get(devURL, verify=False)
        devTree = ET.fromstring(r.text)
        addrList = devTree.findall('.//address/entry')
    else:
        devURL = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/device-group/entry[@name='{dg}']/address&key={mainkey}"
        r = requests.get(devURL, verify=False)
        devTree = ET.fromstring(r.text)
        addrList = devTree.findall('.//address/entry')
    return addrList


# Compares the list from csv file against current set of address objects, prints matches to screen, returns match list
def matchAddressObjects(fwip, mainkey, dg, addrList_mods):
    addrList_current = getAddressObjects(fwip, mainkey, dg)
    addrList_names = []
    addrList_currentMatch = []
    count = 1
    print('Checking list for matches against current address objects...\n\n')
    time.sleep(2)
    for mod_entry in addrList_mods:
        name_new = mod_entry[0]
        ip_new = mod_entry[1]
        for current_entry in addrList_current:
            if current_entry.find('ip-netmask') is not None:
                ip_original = current_entry.find('ip-netmask').text
                name_original = current_entry.get('name')
            else:
                continue
            if ip_original == ip_new:
                if name_original == name_new:
                    print(f'***** Match found: PAN object: {name_original}: {ip_new}\n   -- No change required, since the name already matches the list entry')
                    addrList_currentMatch.append((name_original, name_new, ip_new))
                    continue
                else:
                    print(f'***** Match found: PAN object: {name_original}: {ip_new}\n                -- Changed to: {name_new}: {ip_new}')
                for entry in addrList_names + addrList_currentMatch:
                    if not addrList_names + addrList_currentMatch:
                        break
                    if ip_new == entry[2] and name_new == entry[1]:
                        print(f' ^^-- There was a duplicate - {entry[1]}: {entry[2]} - Already in use...\n      The duplicate object will be named {entry[1]}_DUPLICATE_{str(count)}\n')
                        name_new += f'_DUPLICATE_{str(count)}'
                        count += 1
                        break
                addrList_names.append((name_original, name_new, ip_new))
    pushAddrChanges(fwip, mainkey, dg, addrList_names)


# Pushes the API calls to firewall or Panorama
def pushAddrChanges(fwip, mainkey, dg, addrList_names):
    if not addrList_names:
        print('\n\nThere were no matches between the list provided and the set of address objects on the Panorama/firewall, or there were no changes required\n\n')
    else:
        input('\n\n\nPress Enter to push API calls to Panorama/firewall (or CTRL+C to kill the script)... \n\n\n')
        for entry in addrList_names:
            if dg is None:
                devURL = f"https://{fwip}/api/?type=config&action=rename&xpath=/config/devices/entry/vsys/entry/address/entry[@name='{entry[0]}']&newname={entry[1]}&key={mainkey}"
            else:
                devURL = f"https://{fwip}/api/?type=config&action=rename&xpath=/config/devices/entry/device-group/entry[@name='{dg}']/address/entry[@name='{entry[0]}']&newname={entry[1]}&key={mainkey}"
            r = requests.get(devURL, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == 'success':
                print(f'API push for {entry[0]} change to {entry[1]} was successful')
            else:
                print(f'***** API push error for {entry[0]} change to {entry[1]} *****')


def main():
    dg = None
    if len(sys.argv) < 2:
        print('\n\nThis script requires a csv file passed as a command argument: Example - rename-addr-objects.py exampleCSVfile.csv\n\nPlease try again\n\n\n')
        exit()
    else:
        addrList_mods = [tuple(line.rstrip().split(',')) for line in open(sys.argv[1])]
    fwip = getfwipfqdn()
    mainkey = getkey(fwip)
    devType = getDevType(fwip, mainkey)
    if devType == 'pano':
        while True:
            dg = getDG(fwip, mainkey)
            matchAddressObjects(fwip, mainkey, dg, addrList_mods)
            dgChoice = input('\n\nWould you like to run this script against another device group? [Y/n]  ')
            if not dgChoice or dgChoice.lower() == 'y':
                newList = input('\n\nEnter the name of the address list for this device group, (leave blank to use the same list): ')
                if newList:
                    addrList_mods = [tuple(line.rstrip().split(',')) for line in open(newList)]
                continue
            elif dgChoice.lower() == 'n':
                break
            else:
                print("\n\nChoose '1' or '2', try again...\n")
                time.sleep(1)
    else:
        matchAddressObjects(fwip, mainkey, dg, addrList_mods)
    print('\n\n\nHave a great day!!\n\n')


if __name__ == '__main__':
    main()
