###############################################################################
#
# Script:       rename-addr-objects.py
#
# Author:       Chris Goodwin <chrisgoodwins@gmail.com>
#
# Description:  Checks for name matches between an address object list
#               (in csv format) provided by the user, and the set of address
#               objects on a firewall or Panorama device group. If there is a
#               match, then the PAN address object is renamed to the new object
#               name in the user-provided list. The script takes the csv file
#               as input via command line argument. It can alsooptionally be
#               run in 'practice mode' without making changes by adding the
#               --dry-run flag as a command line argument.
#
# Usage:        rename-addr-objects.py <user-provided-list.csv> [--dry-run]
#
# Requirements: pandevice
#
# Python:       Version 3
#
###############################################################################


import getpass
import sys
import re
import time
from multiprocessing.pool import ThreadPool
try:
    from pandevice import errors
    from pandevice.base import PanDevice
    from pandevice.firewall import Firewall
    from pandevice.panorama import Panorama, DeviceGroup
    from pandevice.objects import AddressObject
except ImportError:
    raise ValueError("pandevice support not available, please install module - run 'py -m pip install pandevice'")


# Global Variables
username = None
password = None
pan_device = None
pano_dg = None
dg_hierarchy = []
overridden_objects = []
dry_run_flag = False


# Prompt the user to enter an address, then checks it's validity
def get_pan_addr():
    while True:
        fwipraw = input("Enter Panorama/firewall IP or FQDN: ")
        ipr = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", fwipraw)
        fqdnr = re.match(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", fwipraw)
        if ipr:
            break
        elif fqdnr:
            break
        else:
            print("\nThere was something wrong with your entry. Please try again...\n")
    return fwipraw


# Prompt the user to enter a username and password
def get_creds():
    while True:
        username = input("Please enter your user name: ")
        usernamer = re.match(r"^[\w-]{3,24}$", username)
        if usernamer:
            password = getpass.getpass("Please enter your password: ")
            break
        else:
            print("\nThere was something wrong with your entry. Please try again...\n")
    return username, password


# Check the validity of both the line and the name entry
def check_list_validity(addr_list_mods):
    name_regex = r'^(?:([A-Za-z\d])|(?:(?:[A-Za-z\d])(?:[\w \.-]){0,61}(?:[\w\.-])))$'
    fail = False
    print('\n')
    for index, item in enumerate(addr_list_mods):
        name_r = re.match(name_regex, item[0])
        if not name_r:
            print(f'ERROR: Line {index + 1} - {item[0]} does not conform to PAN naming convention')
            fail = True
        if len(item) != 2:
            print(f'ERROR: Line {index + 1} - {item} does not contain proper entries, lines must only contain 2 fields: new_object_name,original_object_name')
            fail = True
    if fail is True:
        time.sleep(.75)
        print('\nPlease fix the issue, then try again...\n\n')
        exit()


# Determine whether the device is Panorama or firewall
def get_dev_type(pan_addr):
    global username, password
    while True:
        try:
            pan_device = PanDevice(pan_addr, username, password)
            if pan_device.refresh_system_info().platform.lower() in ['panorama', 'm-100', 'm-200', 'm-500', 'm-600']:
                print('\n\n...Auto-detected device type as Panorama...\n')
                return 'pano'
            else:
                print('\n\n...Auto-detected device type as a firewall...\n')
                return 'fw'
        except errors.PanURLError as e:
            if 'invalid credential' in str(e).lower():
                print('\n\nYour user credentials are invalid, try again...\n\n')
                username, password = get_creds()
            else:
                print('\n\nUnable to connect to device...\n\n')
                exit()


# Get the hierarchy of the current DG
def get_dg_hierarchy(all_dgs):
    global dg_hierarchy
    current_pano_dg = pano_dg
    dg_hierarchy = []
    dg_hierarychy_tree = pan_device.op('show dg-hierarchy')
    while True:
        dg_name = dg_hierarychy_tree.find(f".//*/[@name='{current_pano_dg}']...").get('name')
        if dg_name is None:
            break
        else:
            dg_hierarchy.extend([i for i in all_dgs if i.name == dg_name])
            current_pano_dg = dg_name


def get_pano_dg():
    global pano_dg, pan_device
    all_dgs = pan_device.add(DeviceGroup()).refreshall(pan_device, name_only=True)
    while True:
        try:
            print("\n\nHere's a list of device groups found in Panorama...\n")
            for index, dg in enumerate(all_dgs):
                print(f'{index + 1}) {dg.name}')
            dg_choice = int(input('\n\nChoose a number for the device-group...\n\nAnswer: '))
            pano_dg = all_dgs[dg_choice - 1]
        except:
            print("\n\nThat's not a number in the list, try again...\n")
            time.sleep(.75)
            continue
        get_dg_hierarchy(all_dgs)
        pano_dg.refresh(pan_device)
        pan_device = pano_dg
        break


# Check to see if objects are overridden, if so then skip the object.
# If the script were to take action on an object that is overridden, then pandevice takes the strange
# behavior of renaming ojects with the same name refrenced in address groups in parent device groups
def override_check(addr_list_current_match):
    print('')
    all_parent_objects = []
    for dg in dg_hierarchy:
        all_parent_objects.extend([i.name for i in dg.add(AddressObject()).refreshall(dg, name_only=True, add=False)])
    all_parent_objects.extend([i.name for i in pan_device.add(AddressObject()).refreshall(dg, name_only=True, add=False)])
    for entry in addr_list_current_match[:]:
        if entry[0].name in set(all_parent_objects):
            print(f"NOTE: Address object '{entry[0].name}' exists in a parent device group, and is being overridden\n      The script can't handle this type of object, so it will be skipped")
            addr_list_current_match.remove(entry)
    return addr_list_current_match


# Compare the list from csv file against current set of address objects, prints matches to screen, returns match list
def match_address_objects(addr_list_mods):
    addr_list_current = AddressObject.refreshall(pan_device, add=False)
    addr_list_current_match = []
    count = 1
    print('\n\nChecking list for matches against current address objects...')
    with open('address_object_rename_results.txt', 'w+') as wfile:
        for mod_entry in addr_list_mods:
            name_new = mod_entry[0]
            name_current = mod_entry[1]
            for current_entry in addr_list_current:
                if current_entry.name == name_current:
                    if current_entry.name == name_new:
                        wfile.write(f'***** Match found: Current PAN object: {current_entry.name}: {current_entry.value}\n   -- No change required, since the name already matches the list entry\n\n')
                    else:
                        wfile.write(f'***** Match found: Current PAN object: {current_entry.name}: {current_entry.value}\n                -- Will be changed to: {name_new}: {current_entry.value}\n\n')
                        addr_list_current_match.append([current_entry, name_new, current_entry.value])
        print('\nChecking for duplicates...\n')
        for index, entry in enumerate(addr_list_current_match):
            if not addr_list_current_match:
                break
            if entry[1] in [i.name for i in addr_list_current]:
                print(f'Warning: There was a duplicate - {entry[1]}: {entry[2]} - Already in use...\n         The duplicate object will be named {entry[1]}_DUPLICATE_{str(count)}\n')
                wfile.write(f'Warning: There was a duplicate - {entry[1]}: {entry[2]} - Already in use...\n         The duplicate object will be named {entry[1]}_DUPLICATE_{str(count)}\n\n')
                addr_list_current_match[index][1] = f'{entry[1]}_DUPLICATE_{str(count)}'
                count += 1
    addr_list_current_match = override_check(addr_list_current_match)
    if dry_run_flag:
        input(f'\n\nThere are a total of {len(addr_list_current_match)} objects that will be renamed. These changes have been logged to address_object_rename_results.txt\n\n******* Dry-run flag enabled - No chages will be made *******\n\nHit enter to continue, or CTRL+C to cancel...')
    else:
        input(f'\n\nThere are a total of {len(addr_list_current_match)} objects that will be renamed. These changes have been logged to address_object_rename_results.txt\n\n\nHit enter to push your address changes, or CTRL+C to cancel...')
    return addr_list_current_match


# Pushes the API calls to firewall or Panorama
def push_addr_changes(addr_list_names):
    def multithread(entry):
        for obj in pan_device_obj_list:
            if obj.name == entry[0].name:
                if not dry_run_flag:
                    obj.rename(entry[1])
                print(f'Object name change from {entry[0]} to {entry[1]} was successful')
    if not addr_list_names:
        print('\n\nThere were no matches between the list provided and the set of address objects on the Panorama/firewall, or there were no changes required\n\n')
    else:
        pan_device_obj_list = pan_device.add(AddressObject()).refreshall(pan_device)
    print('\n')
    with ThreadPool(processes=16) as pool:
        pool.map(multithread, addr_list_names)


def main():
    global pan_device, username, password, dry_run_flag
    if len(sys.argv) == 3 and sys.argv[2] == '--dry-run':
        dry_run_flag = True
        print('\n\n\n******* Dry-run flag enabled - No chages will be made *******\n\n')
    elif len(sys.argv) == 2:
        pass
    else:
        time.sleep(.75)
        print('\nERROR: The proper format is rename-addr-objects_multithreaded.py <addr-list.csv> [--dry-run]\n\n')
        exit()
    with open(sys.argv[1], 'r') as rfile:
        print(f"\n\nCSV file found...\n\n")
        addr_list_mods = [tuple(line.rstrip().split(',')) for line in rfile]
    check_list_validity(addr_list_mods)
    pan_addr = get_pan_addr()
    username, password = get_creds()

    # Determine whether this is a Panorama or firewall
    dev_type = get_dev_type(pan_addr)
    if dev_type == 'pano':
        while True:
            pan_device = Panorama(pan_addr, username, password)
            get_pano_dg()
            addr_list_names = match_address_objects(addr_list_mods)
            push_addr_changes(addr_list_names)
            dg_choice = input('\n\nWould you like to run this script against another device group? [Y/n]  ')
            if not dg_choice or dg_choice.lower() == 'y':
                new_list = input('\n\nEnter the name of the address list for this device group, (leave blank to use the same list): ')
                if not new_list:
                    new_list = sys.argv[1]
                with open(new_list, 'r') as rfile:
                    print(f"\n\nCSV file found...\n\n")
                    addr_list_mods = [tuple(line.rstrip().split(',')) for line in rfile]
                check_list_validity(addr_list_mods)
            elif dg_choice.lower() == 'n':
                break
            else:
                print("\n\nChoose '1' or '2', try again...\n")
                time.sleep(.75)
    else:
        pan_device = Firewall(pan_addr, username, password)
        addr_list_names = match_address_objects(addr_list_mods)
        push_addr_changes(addr_list_names)
    print('\n\n\nHave a great day!!\n\n')


if __name__ == '__main__':
    main()
