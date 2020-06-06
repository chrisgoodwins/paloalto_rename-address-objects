# paloalto_rename-address-objects
Enables a user to rename address objects in bulk by comparing a csv file containing new and old object names against the current set of address objects on a firewall or Panorama device group
## Features
- Checks for duplicate objects, and renames accordingly
- Checks new object names for compliance with PAN naming convention
- Run script against multiple device groups, with multiple lists
- Script is multithreaded, so it runs quickly
- Option to run the script in practice mode with --dry-run arg

## Usage
rename-addr-objects.py <user-provided-list.csv> [--dry-run]

CSV list should be in the following format:
```
NEW_address1,OLD_address1
NEW_address2,OLD_address2
NEW_address3,OLD_address3
NEW_network1,OLD_network1
NEW_network2,OLD_network2
```

## Warning
This script pushes an api call for each individual object to be renamed. If you are renaminig a lot of objects at once, this could have an impact on the management plane of your device.

## ToDo
Currently there is no support for objects that are overriding parent device group objects. This will be fixed once a bug is fixed on the upstream pandevice framework
