#! /usr/bin/env python
#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: aniket.khandelwal@nutanix.com
#
# This file implements MIB class which parse the given source
# file and add notification type and object type structure
# in the destination file.

import env
import google.protobuf.text_format as text_format
import re
import utils_mib

from serviceability.plugin_schema_pb2 import *
from string import Template

PATH_MIB = 'NEW-MIB'
NEW_MIB = 'NEW-MIB'

# Wrapper aroud MIB file

class MIB:
  """
  MIB Class contains NtxObject and NtxTrap classes defined
  which are object-type and notification-type structure
  in MIB file. MIB Class contains object and trap list which
  when we parse the source file, we add the existing traps and
  objects in the list. To add a new trap the json file of alert
  is parsed as proto and then converted into NtxTrap Object.
  """
  # Max length of trap name which could be defined.
  MAX_OBJECT_NAME_LIMIT = 64

  # Contains NtxObject Class defined in file.
  Objectlist = []

  # Contains NtxTrap Class defined in file.
  Traplist = []

  # No of object-type defined in file.
  ntx_object_start_oid = 1

  # Used for giving trap their distinct OID in SNMP MIB.
  # Traps are consumed from this OID.
  ntx_trap_start_oid = 1000
  """
  Only these types can be defined for an object type.
  All of the syntax of NtxObject belongs only to one of these.
  """
  AttributeType = ['Integer32', 'Counter64', 'Unsigned32', 'DisplayString']

  def __init__(self, source):
    # Take sourcefile as an input to parse it.
    self.sourcefile = source
    self.read_file(source)

  class NtxObject:
    """
    NtxObject class denotes the object-type structure defined in MIB.
    """
    # Name of object such as ntxCreationTime or ntxDisplayMsg.
    name = ''
    # Synatx whether it is string or integer. 
    syntax = ''
    max_access = 'read-only'
    status = 'current'
    description = ''
    # The last number present in its OID.
    counter = 0
    # OID.
    OID = ''
    # To compare two objects to avoid duplication based on their features.
    def compare(self, obj):
      return (self.name == obj.name and self.syntax == obj.syntax and
        self.max_access == obj.max_access and self.status == obj.status)

  class NtxTrap:
    """
    NtxTrap defined here with attributes.
    It denotes the  notification-type defined in file as NtxTrap.
    """
    # Name of the trap.
    name = ''
    # List of objects which it contains.
    objects = []
    status = 'current'
    description = ''
    # The last number present in its OID.
    counter = 0
    # OID.
    OID =  ''
    # To compare two traps on the basis of their name and status.
    # Name is enough as such no two traps should have same name in file.
    def compare(self, obj):
      return (self.name == obj.name and self.status == obj.status)

  def read_file(self, source):
    """
    Reading a MIB file and add all alert objects such as ntxAlertCreationTime 
    and traps present such as NtxTrap. This function is called when we
    intailise our MIB class.
    """
    def number(string):
      """
      Find first number in the string say in 'nutanix.10' returns 10.
      """
      arr = re.findall(r'\d+', string)
      return int(arr[0])

    def refinesyntax(string):
      """
      Takes a string and finds out the type either int or string
      of NtxTrap or NtxObject class
      """
      # TODO not generic as it depends on spacing we give to split.
      arr = string.split('               ')
      return arr[len(arr) - 1]

    def findlist(file,linecount):
      """
      Read the objects defined in notification-type trap.
      """
      lineadd = ''
      len_brac = 0
      while len_brac != 2:
        lineadd += file[linecount]
        len_brac += file[linecount].count('}')
        linecount += 1
      form_string = re.findall(r'(?<={)[^}]*',lineadd)
      string = re.sub('\s','',form_string[0])
      return string.split(',')

    def read_string_end(file, linecount):
      """
      Parse out the line to find the string within double quotes.
      """
      lineadd = ''
      len_col = 0
      while len_col != 2:
        lineadd += file[linecount]
        len_col += file[linecount].count('"')
        linecount += 1
      form_string =  re.findall(r'(?<=")[^"]*',lineadd)
      return form_string[0]

    # Parse out the OID and return the same.
    def parseOID(line):
      line = re.findall(r'{([^"]*)}',line)
      extract = [ x for x in line[0].split(' ') if x != '' ]
      return '.'.join(extract)

    file = []
    check = 0
    with open(source) as f:
      file = f.readlines()
      linecount = -1
      for line in file:
        linecount += 1
        line = line.rstrip()
        # TODO  Not Generic, Searches for this line defined in file.
        # Assumption : We search this line and only after we find this line
        # we do search all ntx-traps and ntx-objects and parse them.
        if line == '  ntxAlert OBJECT IDENTIFIER ::= {nutanix 999}':
          check = 1
        splitline = line.split(' ')
        splitline = [x for x in splitline if x != '']
        # Check = 1 implies we have searched the above line.
        if check:
          if len(splitline) >= 1:
            if splitline[len(splitline) - 1] == 'OBJECT-TYPE':
              # Initiate a new NtxObject instance.
              obj = self.NtxObject()
              obj.name = splitline[0]
              check = 2
            elif splitline[len(splitline) - 1] ==\
                'NOTIFICATION-TYPE':
              # Initiate a new Trap instance.
              trap = self.NtxTrap()
              trap.name = splitline[0]
              check = 3
            # Split on the choice of notification type or object type.
            if check == 2:
              # Read the contents of object-type.
              if splitline[0] == 'SYNTAX':
                obj.syntax = refinesyntax(line)
              elif splitline[0] == 'MAX-ACCESS':
                obj.max_access = splitline[len(splitline) - 1]
              elif splitline[0] == 'STATUS':
                obj.status = splitline[len(splitline) - 1]
              elif splitline[0] == 'DESCRIPTION':
                obj.description = '"' +  \
                  read_string_end(file,linecount) + '"'
              elif splitline[0] == '::=':
                obj.counter = number(line)
                obj.OID =  parseOID(line)
                # Add the object-type found to MIB class object list.
                self.add_object(obj)
            elif check == 3:
              # Read the contents of notification-type.
              if splitline[0] == 'OBJECTS':
                trap.objects = findlist(file,linecount)
              elif splitline[0] == 'STATUS':
                trap.status = splitline[len(splitline) - 1]
              elif splitline[0] == 'DESCRIPTION':
                trap.description = '"' + \
                  read_string_end(file,linecount) + '"'
              elif splitline[0] == '::=':
                trap.counter = number(line)
                trap.OID  = parseOID(line)
                # Add trap found in the MIB class trap list.
                self.add_trap(trap)

  def dump_object_file(self, obj):
    """
    Writing the NtxObject Template into MIB file.
    """
    s = Template('\n  $name    OBJECT-TYPE\n    SYNTAX         '\
          +'      $syntax\n    MAX-ACCESS           $max_access\n'\
          +'    STATUS               $status\n    DESCRIPTION   '\
          +'       $description\n    ::= {$oid}\n')
    string = s.substitute(name=obj.name,syntax=obj.syntax,max_access=\
            obj.max_access,status=obj.status,description=obj.description\
            ,oid=obj.OID.replace('.',' '))
    return string

  def dump_trap_file(self, obj):
    """
    Writing the NtxTrap Template into MIB file.
    """
    objstring = ''
    for objdef in obj.objects:
      objstring += objdef + ', '
    s = Template('\n  $name   NOTIFICATION-TYPE\n     OBJECTS     '\
          +'        { $string }\n     STATUS                $status\n'\
          +'     DESCRIPTION           $description\n     ::= { nutanix '\
          +'$counter}\n')
    string = s.substitute(name=obj.name,string=objstring[:len(objstring)-2]\
           ,status=obj.status,description=obj.description,counter=\
           obj.counter)
    return string

  def dump_objlist(self):
    """
    Print the object in the Objectlist in file.
    """
    addfile = ''
    for obj in self.Objectlist:
      addfile += self.dump_object_file(obj)
    return addfile

  def dump_traplist(self):
    """
    Print the traps in the Traplist in file.
    """
    addfile = ''
    for obj in self.Traplist:
      addfile += self.dump_trap_file(obj)
    return addfile

  def add_object(self, obj):
    """
    Add a new object-type in MIB object list.
    """
    if(not(sum(map(lambda i: i.compare(obj), self.Objectlist)))):
      self.Objectlist.append(obj)
      self.ntx_object_start_oid = max(self.ntx_object_start_oid,
      obj.counter + 1)

  def add_trap(self, obj):
    """
    Add  a new trap in MIB trap list.
    """
    if(not(sum(map(lambda i: i.compare(obj), self.Traplist)))):
      self.Traplist.append(obj)
      self.ntx_trap_start_oid = max(self.ntx_trap_start_oid, obj.counter + 1)

  def del_object(self, obj):
    """
    Delete Object from the list.
    """
    if obj in self.Objectlist:
      self.Objectlist.remove(obj)

  def del_trap(self, obj):
    """
    Delete Trap from the list.
    """
    if obj in self.Traplist:
      self.Traplist.remove(obj)

  def selecttype(self, tup):
    """
    Define a valid object type for an alert attribute.
    """
    if tup == 'TYPE_INT64' or tup == 'TYPE_BOOL':
      return self.AttributeType[1]
    if tup == 'TYPE_STRING':
      return self.AttributeType[3]
    return self.AttributeType[3]

  def parse_name(self,name):
    """
    Parse the Trap title and keep  only alphanumeric characters.
    """
    name  =  name.split(' ')
    addup = ''
    for word in name:
      if len(word):
        addup += word[0].upper() + word[1:]
    return re.sub(r'[^a-zA-Z0-9]','',addup)

  def alertattr_to_object(self, attr):
    """
    Read attribute name and convert to object-type.
    """
    objectnew = self.NtxObject()
    objectnew.name = 'ntxAlert' + self.parse_name(attr)
    objectnew.syntax = self.selecttype(utils_mib.ATTRIBUTE[attr][0])
    objectnew.max_access = 'read-only'
    objectnew.status = 'current'
    objectnew.description = '"Alert ' + \
      self.parse_name(attr) + ' defined new."'
    objectnew.counter = self.ntx_object_start_oid
    objectnew.OID =  'ntxAlert.' + str(objectnew.counter)
    return objectnew

  def alert_to_trap(self, alert):
    """
    Convert alert details extracted from alert proto in trap object.
    """
    trapnew = self.NtxTrap()
    trap_name = 'ntxTrap' + self.parse_name(alert.alert_config.alert_title)
    if len(trap_name) > self.MAX_OBJECT_NAME_LIMIT:
        trap_name = 'ntxTrap' + str(alert.alert_config.alert_id)
    trapnew.name = trap_name
    trapnew.objects = [ x.name for x in self.Objectlist ]
    trapnew.status = 'current' 
    if alert.HasField('description'):
      trap_description = alert.description
    else:
      trap_description = alert.name.replace('_',' ')
    trapnew.description = '" ' +  trap_description + ' ."'
    trapnew.counter = self.ntx_trap_start_oid
    trapnew.OID = 'nutanix.' + str(trapnew.counter)
    return trapnew

  #----------------Operations available-------------------#

  def find_trap_for_alert(self, alertname):
    """
    Find a trap for a particular alert.
    """
    for trap in self.Traplist:
      if trap.name == 'NtxTrap' + self.parse_name(alertname):
        return trap

  def list_traps(self):
    """
    List all available traps.
    """
    return self.Traplist

  def list_objects(slef):
    """
    List all available objects.
    """
    return self.Objectlist

  def add_object_from_attribute(self, attribute):
    """
    Add an object type from a new attribute.
    """
    self.add_object(self.alertattr_to_object(attribute))

  def add_trap_from_alert(self, config_file):
    """
    Add trap from alert json file.
    """
    psl = PluginSchemaList()
    utils_mib.load_config_file(config_file, psl)
    plugin_schema_list = psl.plugin_schema_list
    for plugin_schema in plugin_schema_list:
      for check_schema in plugin_schema.check_schema_list:
        # Check if the config schema has alert config defined within.
        if check_schema.HasField('alert_config'):
          self.add_trap(self.alert_to_trap(check_schema))

  def apply_changes_file(self):
    """
    Edit the file and dump the changes.
    """
    file = []
    newfile = []
    fileend = 0
    with open(self.sourcefile) as f:
      file = f.readlines()
      i = 0
      # Not Generic as depends on the line location.
      for lines in file:
        if lines == '  ntxAlert OBJECT IDENTIFIER ::= {nutanix 999}\n':
          # Dump the object-type in MIB file.
          lines = lines + self.dump_objlist()
          # Dump the traps defined in MIB file.
          lines += self.dump_traplist()
          lines += 'END\n'
          fileend = 1
        newfile.append(lines)
        if(fileend == 1):
          break
          i += 1
    with open(self.sourcefile, 'w') as f:
      for lines in newfile:
        f.write(lines)

def main():
  y = MIB(PATH_MIB)
  y.add_trap_from_alert(
  '/home/nutanix/ncc/plugin_config/plugin_schema/' +
  'external_checks/network/duplicate_ip_error.json')
  utils_mib.addattribute(PluginSchema.CheckSchema)
  y.add_object_from_attribute('severity')
  y.add_object_from_attribute('name')
  y.apply_changes_file()

if __name__ == "__main__":
  main()
