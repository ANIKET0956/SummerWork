#! /usr/bin/env python
#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: aniket.khandelwal@nutanix.com
#
# This file takes a ncc folder to parse the plugin schema
# and add traps in MIB file for each of such alerts

import os
import sysmib
import utils_mib

from serviceability.plugin_schema_pb2 import *

# Return the list of all plugin schema in ncc.
def parse_all_json(dirlist):
  for root, dirs, files in os.walk("/home/nutanix/ncc/plugin_config/plugin_schema/"):
    for file in files:
      if file.endswith(".json"):
	dirlist.append(os.path.join(root,file))

# Generate a new mib file adding all new alerts.
def generate_new_mib():
  # Take a MIB file as its sourec file.
  y = sysmib.MIB('NEW-MIB')
  utils_mib.addattribute(PluginSchema.CheckSchema)
  # Add new object-type such as name and resolution.
  y.add_object_from_attribute('title')
  y.add_object_from_attribute('severity')
  dirlist = []
  # Search for all json files.
  parse_all_json(dirlist)
  for json in dirlist:
    # Add traps for each alert.
    y.add_trap_from_alert(json)
  # Apply changes to the same file.
  y.apply_changes_file()

if __name__ == "__main__":
  generate_new_mib()

