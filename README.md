# paloalto_rename-address-objects
Enables a user to rename ip-netmask address objects in bulk by comparing a csv file with addresses and new names against the current set of address objects
## Features
- Checks for duplicate objects by address value, renames accordingly
- Automatically recognizes the device type, presents user with choice of device group if Panorama
- Run script against multiple device groups, with multiple lists

## Usage
rename-addr-objects.py <user-provided-list.csv>

CSV list should be in the following format:
```
address1,1.1.1.1
address2,2.2.2.2
address3,3.3.3.3/32
network1,1.1.1.0/24
network2,10.0.0.0/8
```

## Warning
This script pushes an api call for each individual object to be renamed. If you are renaminig a lot of objects at once, this could have an impact on the management plane of your device.
