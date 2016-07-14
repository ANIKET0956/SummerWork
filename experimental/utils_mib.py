#! /usr/bin/env python
#
# Copyright (c) 2016 Nutanix Inc. All rights reserved.
#
# Author: aniket.khandelwal@nutanix.com
#
# This file defines the way to parse the proto schema
# and also add attributes of this proto message in the
# dictonary, such as description, impact, name.

import env
import google.protobuf.text_format as text_format
import google.protobuf.descriptor
import google.protobuf.message
import re

from serviceability.plugin_schema_pb2 import *

# Type defined in Proto buffer descriptor  class
MAPTYPE = { '1' : 'TYPE_DOUBLE' , '2' : 'TYPE_FLOAT' , '3' : 'TYPE_INT64' ,
 '4' : 'TYPE_UNIT64' , '5' : 'TYPE_INT32' , '6' : 'TYPE_FIXED64' ,
'7' : 'TYPE_FIXED32' , '8' : 'TYPE_BOOL' , '9' : 'TYPE_STRING' ,
'10' : 'TYPE_GROUP' , '11' : 'TYPE_MESSAGE' , '12' : 'TYPE_BYTES' ,
'13' : 'TYPE_UINT32' , '14' : 'TYPE_ENUM' }

# Label tag whether it is optional or required
LABELTYPE ={ '1' : 'LABEL_OPTIONAL' , '2' : 'LABEL_REQUIRED' ,
 '3' : 'LABEL_REPEATED' }

ATTRIBUTE = dict()

def load_config_file(config_file,proto_list):
  """
    Read a alert json file and convert it to proto
  """
  with open(config_file) as proto_file:
    try:
      proto_str = proto_file.read()
      text_format.Merge(proto_str,proto_list)
      return proto_list
    except Exception as e:
      print 'Error parsing ' + config_file + ' as protobuf '
  return None

def  addattribute(message):
  """
  It reads the field of message proto and then it 
  stores if a field is of type double,string and others
  and whether it is optional,required or repeated.
  """
  descriptor  =  message.DESCRIPTOR
  # collect all the fields of a proto message class
  fieldList  =  list(descriptor.fields) 
  for field in fieldList:
    ATTRIBUTE[field.name]= (MAPTYPE[str(field.type)],LABELTYPE[str(field.label)])
  ATTRIBUTE['severity'] = (MAPTYPE['3'],LABELTYPE['1'])
  ATTRIBUTE['title']  = (MAPTYPE['9'],LABELTYPE['1'])

if __name__ == "__main__":
    addattribute(AlertConfig)
