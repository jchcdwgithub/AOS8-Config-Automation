import string
from tkinter import W
from webbrowser import get
from xml.sax.xmlreader import AttributesImpl
import requests
import ex_tokens 
import json
import re
import urllib3
import setup
import data_structures
from docx import Document
from pprint import pprint

CONTROLLER_IP = '192.168.1.241'
BASE_URL = f"https://{CONTROLLER_IP}:4343/v1/"
DEFAULT_PATH = '/mm/mynode'
API_ROOT = 'configuration/object/'

API_REF = setup.get_API_JSON_files()

CONFIG_HISTORY = []

TABLE_COLUMNS = {}
OBJECT_IDENTIFIERS = {}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#login/logout and security tokens
def get_security_tokens(usrname, pw):
    """ Internal function that returns the UIDARUBA and the CSRF token after a successful
        authentication or the reason for authentication failure otherwise. """

    UIDARUBA = ''
    X_CSRF_TOKEN = ''
    API_PATH = 'api/login'

    URL = f'{BASE_URL}{API_PATH}'

    payload = {'username': usrname, 'password': pw}
    response = requests.post(URL, data=payload, verify=False)

    if response.status_code == 200:
        response_json = response.json()
        UIDARUBA = response_json['_global_result']['UIDARUBA']
        X_CSRF_TOKEN = response_json['_global_result']['X-CSRF-Token']
        return {'UIDARUBA':UIDARUBA, 'X-CSRF-TOKEN':X_CSRF_TOKEN}
    else:
        STATUS_STR = response_json['_global_result']['status_str']
        return {'status_str': STATUS_STR, }

def write_tokens_to_external_file(tokens):
    """ Takes a dictionary of security tokens and writes them to a temporary external file named ex_tokens.py """

    UID = tokens['UIDARUBA']
    X_CSRF_TOKEN = tokens['X-CSRF-TOKEN']

    to_file = f'UIDARUBA="{UID}"\nX_CSRF_TOKEN="{X_CSRF_TOKEN}"'

    try:
        external_file = open('ex_tokens.py', 'w')
        external_file.write(to_file)
        external_file.close()
    except IOError:
        print('Could not create ex_tokens.py')

def logout():
    """ Logout of the API and end the session. """

    API_PATH = 'api/logout'

    URL = f'{BASE_URL}{API_PATH}'
    
    response = requests.post(URL, verfiy=False)

    if response.status_code != 200:
        STATUS_STR = response.json()['_global_result']['status_str']
        return {'status_str': STATUS_STR}
    else:
        return {'status_str': 'successfully logged out'}


#nodes and hierarchy
def add_node(node_path):
    """ Adds a node to the hierarchy given the node path as a string"""

    API_PATH =  'configuration_node'

    return call_api(API_PATH,config_path=node_path,data={node_path},post=True)

def get_hierarchy():
    """ Returns the configuration hierarchy"""

    API_PATH = 'node_hierarchy'

    URL = build_url(API_PATH,config_path='/md')

    return make_request(URL)

def get_objects():
    """ Gets the list of objects available in the mobility master domain. WARNING this returns a lot of information. """

    URL = add_uid_to_url('')
    
    response = make_request(URL)

    if response.status_code == 200:
        return response.json()
    else:
        return {'status_code':response.status_code,'status_str':response.reason}

def make_request(url, data={}, post=False):
    """ Makes the get/post request based on the parameters given. If data is given, a JSON payload will be constructed
        along with the necessary headers and cookies. """

    cookies = dict(SESSION = ex_tokens.UIDARUBA)
    headers = {'x-csrf-token':ex_tokens.X_CSRF_TOKEN}
    if data != {}:
        headers['ContentType'] = 'application/json'
    if post:
        response = requests.post(url,data=data,headers=headers,cookies=cookies,verify=False)
    else:
        response = requests.get(url,headers=headers,cookies=cookies,verify=False)
    
    if response.status_code != 200:
        return {'status_code':response.status_code, 'status_str':response.reason}
    else:
        return response

def build_hierarchy(full_path):
  """ Given a path i.e /md/HQ/DC or HQ/DC, create all the nodes in the path after /md. """
  
  node_path = full_path.split('/')
  if '' == node_path[0]: node_path = node_path[1:]
  if 'md' == node_path[0].lower(): node_path = node_path[1:]
  node_paths = []

  partial_path = '/md'
  for path in node_path:
    partial_path += '/' + path
    node_paths.append(partial_path)

  return node_paths

def build_profile(profile_name, profile_attributes, attribute_columns, profiles_to_configure):
  """ Build the profile from its provided attributes and the data from the attribute_columns. """

  if not check_that_required_attributes_are_provided(profile_name,profile_attributes,API_REF):
    exit()
  
  profiles = []

  for profile_attribute in profile_attributes:
    if is_nested_profile(profile_attribute):
      build_profile(profile_attribute,profiles_to_configure[profile_attribute],attribute_columns,profiles_to_configure)
    full_attribute_name = profile_name + '.' + profile_attribute
    add_attributes_to_profiles(full_attribute_name,attribute_columns[full_attribute_name],profiles)
    CONFIG_HISTORY += profiles
  
  return profiles

def get_list_of_api_endpoints(ordered_profiles):
  """ Given an ordered list of profiles to configure, extract the endpoint information and return them as a list. """

  api_endpoints = []

  for profile_group in ordered_profiles:
    profile_parts = profile_group[0].split('.')
    api_endpoint = profile_parts[0]
    if api_endpoint not in api_endpoints:
      api_endpoints.append(api_endpoint)
  
  return api_endpoints

def push_profiles_to_network(ordered_configuration_list, profiles):
  """ Given a list of profiles, push them to the network. """

  object_ids = get_object_identifiers()

  for profile_api_endpoint,profile_list in zip(ordered_configuration_list,profiles):
    for profile in profile_list:
      node = profile.pop('node')
      profile_name = get_object_name(profile,object_ids)
      
      print(f"Pushing configuration object {profile_api_endpoint} {profile_name} to {node}:")
      pprint(profile)
      proceed = input("Proceed? (y/n)")
      if proceed == 'y':
        response = call_api(profile_api_endpoint,config_path=node,data=profile,post=True)
        if (response.status_code == 200 and response.json()['_global_result']['_status'] != 0) or response.status_code != 200:
          if response.status_code != 200:
            print(f"Something went wrong while trying to communicate with the MM. HTTP Status Code: {response.status_code}. Exiting...")
            exit()
          else:
            print(f"One or more of the attributes in the configuration profile {profile_name} failed to push:")
            pprint(response.json())
        else:
          print(f'Successfully configuration profile {profile_name} to {node}.')
      else:
        exit()
    print(f"Saving configurations...")
    response = write_mem(path=node)
    if response != 200:
      print(f"Encountered problem when trying to write memory. HTTP Status Code: {response.status_code}. Aborting...")
      exit()
  print(f'All configuration pushed to the network.')

def build_profiles_from_ordered_list(ordered_profiles):
  """ Given an ordered list of profiles to configure, build the profiles from the TABLE_COLUMNS information. """

  profiles = []
  for profile in ordered_profiles:
    current_profiles = []
    profile_type = profile[0].split('.')[0]

    profile_names = TABLE_COLUMNS[profile[0]]
    suffixed_names = []

    for profile_name in profile_names:
      if len(profile_name.split(',')) < 2:
        node = DEFAULT_PATH
        profile_name += f'_{profile_type}'
      else:
        name,node = profile_name.split(',')
        profile_name = name + profile_type
      suffixed_names.append(profile_name)
      current_profiles.append({'node':node})

    TABLE_COLUMNS[profile[0]] = suffixed_names
    for profile_attribute in profile:
      add_attributes_to_profiles(profile_attribute,TABLE_COLUMNS[profile_attribute],current_profiles)
    profiles.append(current_profiles)

  return profiles
    
def build_ordered_configuration_list(profiles_to_configure):
  """ Returns an ordered list of profiles to configure. """

  ordered_configuration_list = []

  for profile in profiles_to_configure:
    for attribute in profiles_to_configure[profile]:
      if is_nested_profile(attribute):
        add_profile_to_ordered_configuration_list(attribute,profiles_to_configure,ordered_configuration_list)
        remove_nested_profile_from_profiles_to_configure(attribute,profiles_to_configure)
    add_profile_to_ordered_configuration_list(profile,profiles_to_configure,ordered_configuration_list)
  
  return ordered_configuration_list

def add_profile_to_ordered_configuration_list(profile,profiles_to_configure,ordered_configuration_list):
  """ Adds the profile and all its attributes to be configured to the ordered list. """

  grouped_attributes = []
  for attribute in profiles_to_configure[profile]:
    grouped_attributes.append(f'{profile}.{attribute}')
  
  ordered_configuration_list.append(grouped_attributes)
  
def remove_nested_profile_from_profiles_to_configure(profile,profiles_to_configure):
  """ Removes the nested profile from the profiles to configure list. """

  profiles_to_configure.pop(profile,None)

def get_object_name(object,object_ids):
  """ Given an API object, return the ID for the object. """
  
  for attribute in object:
    if attribute in object_ids:
      return attribute

def add_attributes_to_profiles(full_attribute_name,attributes,profiles):
  """ Checks against the API that the attributes in the column are correct and adds them to the provided profiles. """
  
  if len(full_attribute_name.split('.')) < 3:
    attribute_type = get_attribute_type(full_attribute_name)
  else:
    prof_name,attribute,_ = full_attribute_name.split('.')
    attribute_type = get_attribute_type(prof_name+'.'+attribute)
    if attribute_type == 'object':
      if attribute not in profiles[0].keys():
        add_object_attribute_to_profiles(prof_name+'.'+attribute,[],profiles)
        return
      else:
        attribute_type = get_attribute_type(full_attribute_name)
    elif attribute_type == 'array':
      add_array_attribute_to_profiles(prof_name+'.'+attribute,profiles)
      return
    
  if attribute_type == 'integer':
    add_integer_attribute_to_profiles(full_attribute_name,attributes,profiles)
  elif attribute_type == 'string':
    add_string_attribute_to_profiles(full_attribute_name,attributes,profiles)
  elif attribute_type == 'object':
    add_object_attribute_to_profiles(full_attribute_name,attributes,profiles)
  else:
    add_boolean_attribute_to_profiles(full_attribute_name,attributes,profiles)

def add_integer_attribute_to_profiles(full_attribute_name,attributes,profiles):
  """ Add the integer attribute to the provided profiles. """
  if len(full_attribute_name.split('.')) < 3:
    full_attribute_name += '.'
  
  prof_name,attribute_name,property_name = full_attribute_name.split('.')

  for profile,attribute in zip(profiles,attributes):
    attribute_number = extract_numbers_from_attribute(attribute)[0] 
    if attribute_number.isdigit():
      attribute_value = int(attribute_number)
      if is_valid_string_or_number(prof_name,attribute_name,attribute_value,property_name=property_name,type="integer"):
        if property_name != '':
          profile[attribute_name][property_name] = attribute_value
        else:
          profile[attribute_name] = attribute_value
      else:
        raise ValueError(f'Invalid value. Number not within acceptable range: {prof_name} {attribute_name}')
    else:
      raise ValueError(f'Attribute {attribute_name} in {prof_name} must be a number.')      

def add_string_attribute_to_profiles(full_attribute_name,attributes,profiles):
  """ Add the string attributes to the provided profiles. """
  if len(full_attribute_name.split('.')) < 3:
    full_attribute_name += '.'
  
  prof_name,attribute_name,property_name = full_attribute_name.split('.')

  if property_name != '' and is_enumerated_property(prof_name,attribute_name,property_name):
      for profile,attribute in zip(profiles,attributes):
        try:
          api_string = data_structures.BOOLEAN_DICT[attribute]
        except KeyError:
          print(f'Value not defined in BOOLEAN_DICT. Please add and try again.')
          exit()
        if string_is_in_enumerated_property_list(prof_name,attribute_name,property_name,api_string):
          profile[attribute_name][property_name] = api_string
        else:
          raise ValueError(f'Invalid value {attribute} in {prof_name}. Fix and try again.')
  else:
    for profile,attribute in zip(profiles,attributes):
      if is_valid_string_or_number(prof_name,attribute_name,attribute,property_name=property_name):
        if property_name != '':
         profile[attribute_name][property_name] = attribute
        else:
          profile[attribute_name] = attribute
      else:
        exit()

def add_array_attribute_to_profiles(full_attribute_name,profiles):
  """ Adds an array attribute to the profile. """

  prof_name,attribute_name = full_attribute_name.split('.')

  for profile in profiles:
    profile[attribute_name] = []

  required_properties = get_required_properties(full_attribute_name)
  
  for required_property in required_properties:
    required_property_path = prof_name + '.' + attribute_name + '.' + required_property
    property_type = get_array_property_type(full_attribute_name,required_property)
    attributes = TABLE_COLUMNS[required_property_path]

    if property_type == 'string' or property_type == 'integer':
      for attribute,profile in zip(attributes,profiles):
        attribute_value = None
        attribute_was_list = False
        possible_attribute_numbers = extract_numbers_from_attribute(attribute)
        if len(possible_attribute_numbers) != 0:
          attribute_was_list = True
          for number in possible_attribute_numbers:
            if is_valid_string_or_number_in_array(required_property_path,int(number),type=property_type):
              attribute_value = int(number)
              profile[attribute_name].append({required_property:attribute_value})
            else:
              raise ValueError(f'Invalid value. {required_property} is incorrectly configured.')
        elif property_type == 'string' and is_enumerated_array_property(required_property_path):
          try:
            attribute_value = data_structures.BOOLEAN_DICT[attribute]
          except KeyError:
            print(f'Entry not in the BOOLEAN_DICT: Add {full_attribute_name}.{required_property}')
            exit()
        else:
          if is_valid_string_or_number_in_array(required_property_path,attribute):
            attribute_value = attribute
          else:
            raise ValueError(f'Invalid value. {required_property} is incorrectly configured.')
        if not attribute_was_list:
          profile[attribute_name].append({required_property:attribute_value})

def is_enumerated_array_property(full_attribute_name):
  """ Returns True if the array property is an enumeration. """

  prof_name,attribute_name,property_name = full_attribute_name.split('.')

  for ref in API_REF:
    if prof_name in ref['definitions'].keys():
      return "enum" in ref['definitions'][prof_name]['properties'][attribute_name]['items']['properties'][property_name].keys()
        
    
def is_valid_string_or_number_in_array(full_attribute_name,attribute,type='string'):
  """ Returns True if the value is valid in the array. """

  min_len = get_array_attribute_min_length(full_attribute_name)
  max_len = get_array_attribute_max_length(full_attribute_name)
  attribute_len = 0

  if type == 'string':
    attribute_len = len(attribute)
  else:
    attribute_len = int(attribute)

  return attribute_len <= max_len and attribute_len >= min_len    

def get_array_attribute_min_length(full_attribute_name):
  """ Returns the minimum length of the array attribute. """
  
  prof_name,attribute_name,property_name = full_attribute_name.split('.')

  for ref in API_REF:
    if prof_name in ref['definitions'].keys():
      return ref['definitions'][prof_name]['properties'][attribute_name]['items']['properties'][property_name]['minimum']

def get_array_attribute_max_length(full_attribute_name):
  """ Returns the maximum length of the array attribute. """
  
  prof_name,attribute_name,property_name = full_attribute_name.split('.')

  for ref in API_REF:
    if prof_name in ref['definitions'].keys():
      return ref['definitions'][prof_name]['properties'][attribute_name]['items']['properties'][property_name]['maximum']

def get_array_property_type(full_attribute_name,property):
  """ Returns the type of the property inside the array. """

  prof_name,attribute_name = full_attribute_name.split('.')

  for ref in API_REF:
    if prof_name in ref['definitions']:
      return ref['definitions'][prof_name]['properties'][attribute_name]['items']['properties'][property]['type']

def add_object_attribute_to_profiles(full_attribute_name,attributes,profiles):
  """ Adds the object attributes to the profiles. """

  _,attribute_name = full_attribute_name.split('.')
  required_properties = get_required_properties(full_attribute_name)

  for profile in profiles:
    profile[attribute_name] = {}

  if len(required_properties) == 0:
    properties = get_attribute_properties(full_attribute_name)
    if len(properties) != 0:
      add_boolean_attribute_to_profiles(full_attribute_name,attributes,profiles)

  else:
    for required_property in required_properties:
      required_property_path = full_attribute_name + '.' + required_property
      add_attributes_to_profiles(required_property_path,TABLE_COLUMNS[required_property_path],profiles)

def get_attribute_properties(full_attribute_name):
  """ Returns a list of properties for the attribute or an empty list. """

  if len(full_attribute_name.split('.')) < 3:
    full_attribute_name += '.'

  prof_name,attribute_name,property_name = full_attribute_name.split('.')

  for ref in API_REF:
    if prof_name in ref['definitions']:
      if property_name != '':
        try:
          properties = [property for property in ref['definitions'][prof_name]['properties'][attribute_name]['properties'][property_name]['properties'].keys()]
        except KeyError:
          return []
      else:
        try:
          properties = [property for property in ref['definitions'][prof_name]['properties'][attribute_name]['properties'].keys()]
        except KeyError:
          return []
      return properties

def add_boolean_attribute_to_profiles(full_attribute_name,attributes,profiles):
  """ Adds boolean attributes to the profiles. """

  if len(full_attribute_name.split('.')) < 3:
    full_attribute_name += '.'
  
  _,attribute_name,property_name = full_attribute_name.split('.')

  for attribute,profile in zip(attributes,profiles):
    attribute = attribute.replace(' ','')
    attribute_list = attribute.split(',')
    value = ''
    for item in attribute_list:
      if item in data_structures.BOOLEAN_DICT.keys():
        if item == 'True' or item == 'False':
          if property_name != '':
            profile[attribute_name][property_name] = data_structures.BOOLEAN_DICT[item]
            return
          else:
            profile[attribute_name] = data_structures.BOOLEAN_DICT[item]
            return
        else:
          value = data_structures.BOOLEAN_DICT[item]
      elif item.isdigit():
        value = item
      else:
        raise ValueError(f'Invalid value for item {item} in {_}')

      if property_name != '':
        profile[attribute_name][property_name] = value
      else:
        profile[attribute_name][value] = True

def attribute_is_valid(full_attribute_name,attribute):
  """ Given a full attribute name, check the API to make sure the attribute is valid or not. """

  if len(full_attribute_name.split('.')) < 3:
    full_attribute_name += '.'
  prof_name,attribute_name,property_name = full_attribute_name.split('.')
  
  attribute_type = get_attribute_type(full_attribute_name)

  return is_valid_string_or_number(prof_name,attribute_name,attribute,property_name=property_name,type=attribute_type)

def add_boolean_attributes_to_profile(prof_name,attribute_name,attribute,profile):
  """ Adds the boolean values to the attribute object in the profile. """

  boolean_list = attribute.split(',')
  digit_pattern = re.compile(r'\d+')

  for boolean in boolean_list:
    if digit_pattern.match(boolean) is not None:
      if property_is_in_properties(prof_name,attribute_name,boolean):
        profile[attribute_name][boolean] = True
    elif boolean in data_structures.BOOLEAN_DICT.keys():
      profile[attribute_name][boolean] = True
    else:
      print(f'Invalid value encountered in {prof_name}: {boolean} not an excepted value.')
      exit()

def property_is_in_properties(prof_name,attribute_name,property):
  """ Checks whether the property is in the properties of the given attribute. Returns True if so. """

  for ref in API_REF:
    if prof_name in ref["definitions"].keys():
      if property in ref["definitions"][prof_name]["properties"][attribute_name]["properties"]:
        return True
      else:
        return False

def get_required_properties(full_attribute_name):
  """ Returns the required properties list or an empty list. """

  prof_name,attribute_name= full_attribute_name.split('.')

  for ref in API_REF:
    if prof_name in ref["definitions"].keys():
      try:
        if get_attribute_type(full_attribute_name) == 'array':
          required = ref["definitions"][prof_name]["properties"][attribute_name]["items"]["required"]
        else:
          required = ref["definitions"][prof_name]["properties"][attribute_name]["required"]
        return required
      except KeyError:
        return []


def add_string_attribute(profile_name,attribute_name,attributes,profiles):
  """ Adds non-nested string attributes to the profiles. """

  for attribute,profile in zip(attributes,profiles):
    if is_valid_string_or_number(profile_name,attribute_name,attribute):
      profile[attribute_name] = attribute
    else:
      exit()

def is_valid_string_or_number(profile_name,attribute_name,attribute,property_name="",type="string"):
  """ Checks the API reference to ensure that the input is valid. """
  
  min_len = get_attribute_min_len(profile_name,attribute_name,property_name)
  max_len = get_attribute_max_len(profile_name,attribute_name,property_name)

  if type == "string":
    current_len = len(attribute)
  else:
    current_len = attribute
  
  return current_len >= min_len and current_len <= max_len

def get_attribute_min_len(profile_name,attribute_name,property_name=""):
  """ Returns the minimal value for an attribute, property_name should exist for nested attributes. """

  if property_name != "":
    for ref in API_REF:
      if profile_name in ref["definitions"]:
        if get_attribute_type(profile_name+'.'+attribute_name) == 'array':
          return ref["definitions"][profile_name]["properties"][attribute_name]["items"]["properties"][property_name]["minimum"]
        return ref["definitions"][profile_name]["properties"][attribute_name]["properties"][property_name]["minimum"]
  else:
    for ref in API_REF:
      if profile_name in ref["definitions"]:
        return ref["definitions"][profile_name]["properties"][attribute_name]["minimum"]

def get_attribute_max_len(profile_name,attribute_name,property_name=""):
  """ Returns the maximum value for an attribute, property_name should exist for nested attributes. """

  if property_name != "":
    for ref in API_REF:
      if profile_name in ref["definitions"]:
        if get_attribute_type(profile_name+'.'+attribute_name) == 'array':
          return ref["definitions"][profile_name]["properties"][attribute_name]["items"]["properties"][property_name]["maximum"]
        return ref["definitions"][profile_name]["properties"][attribute_name]["properties"][property_name]["maximum"]
  else:
    for ref in API_REF:
      if profile_name in ref["definitions"]:
        return ref["definitions"][profile_name]["properties"][attribute_name]["maximum"]

def attribute_has_properties(full_attribute_name):
  """ Checks whether the attribute has a properties key. Returns True if it does. """

  profile_name,attribute_name = full_attribute_name.split('.')

  for ref in API_REF:
    if profile_name in ref["definitions"]:
      if "properties" in ref["definitions"][profile_name][attribute_name].keys():
        return True
      else:
        return False

def get_object_property_name(full_attribute_name):
  """ Gets the property name of the object. """

  profile_name,attribute_name = full_attribute_name.split('.')

  for ref in API_REF:
    if profile_name in ref["definitions"]:
      return list(ref["definitions"][profile_name]["properties"][attribute_name]["properties"].keys())
  
  return []

def is_enumerated_property(profile_name,attribute_name,property_name):
  """ Returns true if the property is an enumerated property. """

  for ref in API_REF:
    if profile_name in ref["definitions"]:
      return "enum" in ref["definitions"][profile_name]["properties"][attribute_name]["properties"][property_name].keys()

def string_is_in_enumerated_property_list(profile_name,attribute_name,property_name,string):
  """ Validates whether the string is an allowed value for an enumerated object. """

  for ref in API_REF:
    if profile_name in ref["definitions"]:
      return string in ref["definitions"][profile_name]["properties"][attribute_name]["properties"][property_name]["enum"]

def validate_attribute(full_attribute_name):
  """ Checks against the API_REF that the configured attribute is acceptable i.e. between a certain number range or is not a string that's too long, etc."""

def get_attribute_type(full_attribute_name):
  """ Returns the type of the attribute as checked against the API_REF. """

  if len(full_attribute_name.split('.')) < 3:
    full_attribute_name += '.'
  profile_name,attribute_name,property_name = full_attribute_name.split('.')

  for ref in API_REF:
    if profile_name in ref['definitions']:
      if property_name != '':
        return ref['definitions'][profile_name]['properties'][attribute_name]['properties'][property_name]['type']
      else: 
        return ref['definitions'][profile_name]['properties'][attribute_name]['type']

def extract_numbers_from_attribute(attribute):
  """ For integer attributes, remove any text that might have been included i.e. units like dBm. """

  numbers = re.compile(r'\d+')
  extract_numbers = numbers.findall(attribute)
  if len(extract_numbers) == 0:
    return []
  else:
    return extract_numbers

def is_nested_profile(profile_attribute):
  """ If an attribute points to another profile then it is a nested profile. Returns True or False. """

  nested_ending = re.compile(r'.+_prof$')

  if nested_ending.match(profile_attribute) is None:
    return False

  else:
    return True  


def get_profile_names(profile_name_col, suffix=""):
  """ Gets the profile names column from the provided table and return a list of names appended with the optional suffix. """

  return [name.text+suffix for name in profile_name_col]

def add_tx_power_to_radio_profiles(radio_profiles,tx_power_col,attribute):
  """ Given a list of  radio profiles, add the tranmist powers from the table column provided. Attribute is a two tuple of attribute outer name
      and attribute inner name i.e. ('eirp_min','eirp-min') """
  
  remove_dbm = re.compile(r'(\d{1,2})')
  for radio_profile,tx_power in zip(radio_profiles, tx_power_col):
    transmit_power = int(remove_dbm(tx_power.text))
    radio_profile[attribute[0]] = {attribute[1]: transmit_power}

def build_radio_transmit_power_profiles(columns):
  """ Get the profile names, min EIRP, max EIRP from the columns provided and return an array of radio profiles. """

  RF_profile_column = columns['RF Profile']
  min24_column = columns['2.4 GHz Minimum']
  max24_column = columns['2.4 GHz Maximum']
  min5_column = columns['5 GHz Minimum']
  max5_column = columns['5 GHz Maximum']

  g_profile_names = get_profile_names(RF_profile_column,suffix='_radio_g_prof')
  a_profile_names = get_profile_names(RF_profile_column,suffix='_radio_a_prof')

  g_profiles = [{'profile-name':g_profile_name for g_profile_name in g_profile_names}]
  a_profiles = [{'profile-name':a_profile_name for a_profile_name in a_profile_names}]

  add_tx_power_to_radio_profiles(g_profiles,min24_column,('eirp_min','eirp-min'))
  add_tx_power_to_radio_profiles(g_profiles,max24_column,('eirp_max','eirp-max'))
  add_tx_power_to_radio_profiles(a_profiles,min5_column,('eirp_min','eirp-min'))
  add_tx_power_to_radio_profiles(a_profiles,max5_column,('eirp_max','eirp-max'))

  return [g_profiles,a_profiles]

def get_radio_transmit_powers(table):
  """ Given a table of radio transmit powers, configure a and g radio profiles. Profile names 
      are taken from the RF profile column and appended with _g_radio_prof or _a_radio_prof. """

  table_rows =[]

  table_rows = extract_row_cells_from_table(table)

  radio_profiles_24Ghz = []
  radio_profiles_5Ghz = []

  strip_dbm = re.compile(r'\d+')

  for row in table_rows:
    profile_name = row[0].text
    min24 = strip_dbm.match(row[1].text).group(0)
    max24 = strip_dbm.match(row[2].text).group(0)
    min5 = strip_dbm.match(row[3].text).group(0)
    max5 = strip_dbm.match(row[4].text).group(0)

    radio_g_profile = {"profile-name":profile_name+'_g_radio_prof',
        "eirp_min": {
            "eirp-min": int(min24)
        },"eirp_max": {
            "eirp-max": int(max24)
        },}
    radio_a_profile = {"profile-name":profile_name+'_a_radio_prof',
        "eirp_min": {
            "eirp-min": int(min5)
        },"eirp_max": {
            "eirp-max": int(max5)
        },}

    radio_profiles_24Ghz.append(radio_g_profile)
    radio_profiles_5Ghz.append(radio_a_profile)

  return [radio_profiles_24Ghz,radio_profiles_5Ghz]

def get_ap_groups_from_tables(tables):
  """ Configures an AP group and all the Virutal APs that goes into the group from information found in tables. """

  group_names = get_column_from_table('RF Profile', tables['RF Transmit Power'])

  print('Gathering radio profiles...')
  radio_profile_24Ghz,radio_profile_5Ghz = get_radio_transmit_powers(tables['RF Transmit Power'])
  print('Radio profiles gathered.')
  print('Gathering regulatory domain profiles...')
  reg_domain_profiles = get_regulatory_domain_profile_from_table(tables['RF Channel Plan'])
  print('Regulatory domain profiles gathered.')

  ap_groups = [{
  "profile-name": f'{group_name.text}_ap_group',
  "virtual_ap": [
  ]
  } for group_name in group_names]

  for ap_group,rad_24,rad_5,reg_domain in zip(ap_groups,radio_profile_24Ghz,radio_profile_5Ghz,reg_domain_profiles):
    ap_group["dot11a_prof"] = {"profile-name":rad_5["profile-name"]}
    ap_group["dot11g_prof"] = {"profile-name":rad_24["profile-name"]}
    ap_group["reg_domain_prof"] = {"profile-name":reg_domain["profile-name"]}
    
  return [ap_groups,radio_profile_5Ghz,radio_profile_24Ghz,reg_domain_profiles]

def configure_ap_groups(tables):
  """ Push configuration for all profiles found under an AP group. All profile information can be found in the tables. """

  print('Gathering AP groups...')
  ap_groups,radio_profile_5Ghz,radio_profile_24Ghz,reg_domain_profiles = get_ap_groups_from_tables(tables)
  print('Gathering virtual AP profiles...')
  vap_profiles = get_vap_prof_from_tables(tables)

  
  membership_table = tables['WLAN Structure']
  AP_Group_column = get_column_from_table('AP Group',membership_table)
  membership = zip(vap_profiles,AP_Group_column)

  trailing = re.compile(r'(\w+)_ap_group')
  for vap_profile,member in membership:
    for ap_group in ap_groups:
        group_name = trailing.match(ap_group['profile-name']).group(1)
        if member.text == 'All' or group_name in member.text:
            ap_group['virtual_ap'].append({"profile-name":vap_profile["profile-name"]})

  print('Gathering SSID profile information...')
  ssid_profiles = get_ssid_prof_from_tables(tables)
  print('SSID profile information gathered')

  response_history = []

  print('Configuring a radio profiles...')
  response_history += configure_profiles('ap_a_radio_prof',radio_profile_5Ghz,path='/md')
  print('Configuring g radio profiles...')
  response_history += configure_profiles('ap_g_radio_prof',radio_profile_24Ghz,path='/md')
  print('Configuring regulatory domain profiles...')
  response_history += configure_profiles('reg_domain_prof',reg_domain_profiles,path='/md')
  print('Configuring SSID profiles...')
  response_history += configure_profiles('ssid_prof',ssid_profiles,path='/md')
  print('Configuring virtual AP profiles...')
  response_history += configure_profiles('virtual_ap',vap_profiles,path='/md')
  print('Configuring AP group profiles...')
  response_history += configure_profiles('ap_group',ap_groups,path='/md')

  print('Successfully configured network. Complete configuration history:')

  for response in response_history:
    pprint(response)

def configure_profiles(api_endpoint,profiles,path=DEFAULT_PATH):
  """ Configures a group of profiles based on the profiles passed in the profiles paramater. Returns an
      array of responses. """

  response_history = []

  print("Pushing Configuration to the network...")

  for profile in profiles:
    response = call_api(api_endpoint,data=profile,config_path=path,post=True)
    if response.status_code != 200:
      response_history.append({'status_code':response.status_code, 'status_str':response.reason})
    elif response.status_code == 200 and response.json()['_global_result']['status'] != 0:
      response_history.append(response.json())
      print(f'Failed to configure ssid: {profile["profile-name"]}, purging configuration and aborting.')
      purge_pending_config(path=path)
      for response in response_history:
        pprint(response)
      exit()
    else:
      response_history.append(response.json())

  print("Successfully pushed configurations. Configurations pushed:")
  for response in response_history:
    pprint(response)
  print("Committing configurations.")
  write_mem(path='/md')
  print("Successfully committed configuration.")

  return response_history

def get_regulatory_domain_profile_from_table(table):
  """ Returns an array of regulatory domain profiles from the given table. """

  table_rows = []

  table_rows = extract_row_cells_from_table(table)

  reg_domain_profiles = []

  for row in table_rows:
    #profile name with _reg_domain_prof attached
    profile_name = row[0].text + '_reg_domain_prof'
    if row[1].text != 'N/A':
      g_channels = [int(channel) for channel in row[1].text.split(',')]
    a_channels = [int(channel) for channel in row[2].text.split(',')]
    reg_domain_profile = {"profile-name":profile_name,
                         "country_code":{"country-code":"US"},
                         "valid_11a_channel":[{"valid-11a-channel":channel} for channel in a_channels]}
    if row[1].text != 'N/A':
      reg_domain_profile["valid_11b_channel"] = [{"valid-11g-channel":channel} for channel in g_channels]

    reg_domain_profiles.append(reg_domain_profile)

  return reg_domain_profiles

def get_ssid_prof_from_tables(tables):
  """ Given the tables in the document, extract SSID profile data and return an array of SSIDs. """
  
  ssid_profiles = [{
        "profile-name": f'{cell.text}_ssid_prof' ,
        "ssid_enable": {},
        "essid": {
            "essid": cell.text
        },
        "wmm": {},
        "mcast_rate_opt": {},
        "okc_enable": {},
        "mbo_enable": {},
        } for cell in get_column_from_table('WLAN ESSID',tables['WLAN Structure'])] 
  
  add_ssid_info_from_mobility_features_tables(ssid_profiles, tables['WLAN Mobility Features'])
  add_ssid_info_from_advanced_features_tables(ssid_profiles, tables['WLAN Advanced Features'])
  add_ssid_info_from_qos_tables(ssid_profiles, tables['WLAN QoS'])
  add_ssid_info_from_security_tables(ssid_profiles, tables['WLAN Security'])

  return ssid_profiles

def add_ssid_info_from_mobility_features_tables(ssid_profiles, table):
  """ Gets the OKC and 802.11r information from the ssid_profiles in the mobility features table. Returns an array of ssid_profiles. """

  try:
    dot11r_column = get_column_from_table('802.11r',table)
    okc_column = get_column_from_table('OKC',table)
  except ValueError:
    print('802.11r and OKC columns must exist in the WLAN Mobility Features Table.')
    exit()

  dot11r_state = zip(ssid_profiles,dot11r_column)
  okc_state = zip(ssid_profiles,okc_column) 

  for ssid_profile,state in dot11r_state:
    if state.text == 'Disabled':
      ssid_profile.pop('dot11r_prof')
    else:
      base_name = ssid_profile['profile-name'].split('_')[0]
      ssid_profile['dot11r_prof'] = {"profile-name":f'{base_name}_dot11r_prof'}
  
  for ssid_profile,state in okc_state:
    if state.text == 'Disabled':
      ssid_profile.pop('okc_enable')

def add_ssid_info_from_advanced_features_tables(ssid_profiles, table):
  """ Gets the DTIM and MC/BC optimization information from the table and applies it to the SSID profile. """

  try:
    DTIM_column = get_column_from_table('DTIM',table)
    MBO_column = get_column_from_table('BC/MC Rate Optimization',table)
  except ValueError:
    print("DTIM and BC/MC Rate Optimization columns must exist in the WLAN Advanced Features Table.")
    exit()

  DTIM_state = zip(ssid_profiles,DTIM_column)
  MBO_state = zip(ssid_profiles,MBO_column)

  for ssid_profile,state in DTIM_state:
    ssid_profile['dtim_period'] = {'dtim-period':int(state.text)}
  
  for ssid_profile,state in MBO_state:
    if state.text == 'Disabled':
      ssid_profile.pop('mbo_enable')

def add_ssid_info_from_qos_tables(ssid_profiles, table):
  """ Gets the WMM information from the table and applies it to the SSID profiles. """

  try:
    WMM_DSCP_column = get_column_from_table('WMM DSCP',table)
  except ValueError:
    print('WMM DSCP column missing from the QoS Table.')
    exit()

  WMM_DSCP_state = zip(ssid_profiles,WMM_DSCP_column)

  ac_name_mapping = {'AC_VO':'wmm_vo_dscp','AC_VI':'wmm_vi_dscp','AC_BE':'wmm_be_dscp','AC_BK':'wmm_bk_dscp'}

  for ssid_profile,state in WMM_DSCP_state:
    if state.text != 'Default':
      AC_name,DSCP_number = state.text.split(' ')
      ssid_profile[ac_name_mapping[AC_name]] = {ac_name_mapping[AC_name].replace('_','-') : DSCP_number}
      ssid_profile['wmm_dscp_mapping'] = {}

def add_ssid_info_from_security_tables(ssid_profiles, table):
  """ Gets the encryption and MFP/PMF information from the security table and adds it to the SSID profiles. """

  try:
    encryption_column = get_column_from_table('Authentication Type',table)
    mfp_column = get_column_from_table('MFP/PMF',table)
  except ValueError:
    print('Authentication Type and MFP/PMF columns must exist in the WLAN Security Table.')
    exit()

  encryption_state = zip(ssid_profiles,encryption_column)
  mfp_state = zip(ssid_profiles,mfp_column)

  encryption_type_mappings = {'WPA2-Enterprise':'wpa2-aes','WPA2-Personal + MAC':'wpa2-psk-aes','WPA2-Personal':'wpa2-psk-aes','MAC':'opensystem','WPA3-Enterprise':'wpa3-aes-ccm-128','WPA3-Personal':'wpa3-sae-aes'}

  for ssid_profile,state in encryption_state:
    ssid_profile['opmode'] = {encryption_type_mappings[state.text]:True}
    if 'Personal' in state.text:
      ssid_profile['wpa_passphrase'] = {'wpa-passphrase':'CDWcdw123'}

  for ssid_profile,state in mfp_state:
    if state.text == 'Required':
      ssid_profile['mfp_required'] = {}
      ssid_profile['mfp_capable'] = {}
    elif state.text == 'Optional':
      ssid_profile['mfp_capable'] = {}

def get_vap_prof_from_tables(tables):
  """ Get the virtual AP profiles from the tables and return a dictionary with all attributes defined in the tables. """
  
  vap_profiles = [{
  "profile-name": cell.text,
  "vap_enable": {},
  "allowed_5g_radio": {
    "allowed_5g_radio": 'all'
  },
  "dos_prevention": {},
} for cell in get_column_from_table('WLAN ESSID',tables['WLAN Structure'])] 

  vap_profiles = add_11k_profiles_from_mobility_features_table(vap_profiles, tables['WLAN Mobility Features'])
  vap_profiles = add_11r_profiles_from_mobility_features_table(vap_profiles, tables['WLAN Mobility Features'])
  vap_profiles = add_attributes_from_advanced_features_table(vap_profiles, tables['WLAN Advanced Features'])
  vap_profiles = add_attributes_from_access_control_table(vap_profiles, tables['Access Control'])
  vap_profiles = add_attributes_from_WLAN_structure_table(vap_profiles, tables['WLAN Structure'])

  ssid_profiles = get_ssid_prof_from_tables(tables)

  for vap_profile,ssid_profile in zip(vap_profiles,ssid_profiles):
    vap_profile['ssid_prof'] = {'profile-name':ssid_profile['profile-name']}

  for vap_profile,aaa_prof in zip(vap_profiles,['default-dot1x','default-dot1x-psk','default-mac-auth','default-dot1x-psk']):
    vap_profile['aaa_prof'] = {'profile-name':aaa_prof}

  return vap_profiles


def add_11k_profiles_from_mobility_features_table(vap_profiles, table):
  """ Configures and adds the 11k profiles to the vap profiles. """

  try:
    dot11k_column = get_column_from_table('802.11k',table)
  except ValueError:
    print('Dot11k column absent from the mobility features table. Please add it and try again.')
    exit()

  dot11k_state = zip(vap_profiles,dot11k_column)

  print("Pushing 802.11k configuration to the network.")

  for vap_profile,state in dot11k_state:
    if state.text == 'Enabled':
      dot11k_prof = {"profile-name":f'{vap_profile["profile-name"]}_dot11k_prof'}

      response = call_api('dot11k_prof',data=dot11k_prof,config_path='/md',post=True)
      if (response.status_code == 200 and response.json()['_global_result']['status'] != 0) or response.status_code != 200:
        print(f'Failed configuration for {vap_profile["profile-name"]}, purging pending configurations.')
        purge_pending_config('/md')
        return vap_profiles
      else:
        vap_profile['dot11k_prof'] = dot11k_prof

  print("Successfully pushed 802.11k configuration to the network. Committing configuration...")
  write_mem(path='/md')
  print("Successfully committed 802.11k configurations to the network.")

  return vap_profiles

def add_11r_profiles_from_mobility_features_table(vap_profiles, table):
  """ Configures the dot11r profiles to the network to be added to the SSIDs later. """
  try:
    dot11r_column = get_column_from_table('802.11r',table)
  except ValueError:
    print('Dot11r column absent from the mobility features table. Please add it and try again.')
    exit()
  
  dot11r_state = zip(vap_profiles,dot11r_column)

  print('Adding 802.11r profiles to the network.')

  for vap_profile,state in dot11r_state:
    if state.text == 'Enabled':
      dot11r_prof = {"profile-name":f'{vap_profile["profile-name"]}_dot11r_prof'}
      response = call_api('dot11r_prof',data=dot11r_prof,config_path='/md',post=True)
      if (response.status_code == 200 and response.json()['_global_result']['status'] != 0) or response.status_code != 200:
        print(f'Failed configuration for {vap_profile["profile-name"]}, purging pending configurations.')
        purge_pending_config('/md')
        return vap_profiles
      else:
        pprint(response.json())

  print("Successfully pushed 802.11r configuration to the network. Comitting configuration...")
  write_mem(path='/md')
  print("Configuration pushed.")

  return vap_profiles

def add_attributes_from_advanced_features_table(vap_profiles, table):
  """ Adds dynamic mcast, band steering and steering mode to VAP profiles in vap_profiles. """
  try:
    bc_rate_opt_column = get_column_from_table('BC/MC Rate Optimization',table)
    dynamic_mcast_column = get_column_from_table('Dynamic Multicast',table)
    band_steering_column = get_column_from_table('Band Steering',table)
  except ValueError:
    print('Column not found. Please check that the BC/MC Rate Optimization, Dynamic Multicast and Band Steering columns are in the Advanced Features Table.')
    exit()

  dynamic_mcast_state = zip(vap_profiles,bc_rate_opt_column)
  band_steering_state = zip(vap_profiles,dynamic_mcast_column,band_steering_column)

  for vap_profile,state in dynamic_mcast_state:
    if state.text == 'Enabled':
      vap_profile["dynamic_mcast_optimization"] = {}

  steering_mode_mapping = {'Prefer-5GHz':'prefer-5ghz','Force-5GHz':'force-5ghz','Balance':'balance-bands'}
  
  for vap_profile,steering_state,steering_mode in band_steering_state:
    if steering_state.text == 'Enabled':
      vap_profile['band_steering'] = {}
      vap_profile['steering_mode'] = {'steering_mode':steering_mode_mapping[steering_mode.text]}
  
  return vap_profiles

def add_attributes_from_access_control_table(vap_profiles, table):
  """ Deny or restrict inter user vlan traffic. """

  try:
    deny_inter_user_traffic_column = get_column_from_table('Inter User Traffic',table)
  except ValueError:
    print("Inter User Traffic Column not found in the Access Control Table. Please add it and try again.")
    exit()

  inter_user_vlan_state = zip(vap_profiles,deny_inter_user_traffic_column)

  for vap_profile,state in inter_user_vlan_state:
    if state.text == 'Denied':
      vap_profile["deny_vap_inter_user_traffic"] = {}

  return vap_profiles

def add_attributes_from_WLAN_structure_table(vap_profiles, table):
  """ Adds the VLAN, forwarding mode and allowed RF bands to the VAP profiles in vap_profiles. """

  try:
    vlan_state_column = get_column_from_table('VLAN Mapping',table)
    forwarding_mode_column = get_column_from_table('Forwarding Mode',table)
    rf_band_column = get_column_from_table('Frequency Bands',table)
  except ValueError:
    print('VLAN Mapping, Forwarding Mode and Frequency Bands columns must be defined in the WLAN Structure Table.')
    exit()
    
  vlan_state = zip(vap_profiles,vlan_state_column)
  forwarding_mode_state = zip(vap_profiles,forwarding_mode_column)
  rf_band_state = zip(vap_profiles,rf_band_column)

  for vap_profile,state in vlan_state:
    vap_profile["vlan"] = {"vlan":state.text}

  for vap_profile,state in forwarding_mode_state:
    vap_profile['forward_mode'] = {'forward_mode':state.text.lower()}

  rf_band_mapping = {'A-Only':'a','G-Only':'g','All':'all'}

  for vap_profile,state in rf_band_state:
    vap_profile["vap_rf_band"] = {"rf_band_tristate":rf_band_mapping[state.text]}

  return vap_profiles

# filter processing
def sanitize_filter(filter):
    """ Given a JSON filter, replace brackets, commas, etc. with AOS sanitized symbols. """

    #replace quotes with %22
    filter = filter.replace('"','%22')

    #replace opening brackets with %5B
    filter = filter.replace('[','%5B')

    #replace opening curly brackets with %7B
    filter = filter.replace('{','%7B')

    #replace colons with %3A
    filter = filter.replace(':','%3A')

    #replace bling with %24
    filter = filter.replace('$','%24')

    #replace forward slashes with %2F
    filter = filter.replace('/','%2F')

    #replace comma with %2C
    filter = filter.replace(',','%2C')

    #replace closing curly brackets with %5D
    filter = filter.replace(']','%5D')

    #replace closing hard brackets with %7D
    filter = filter.replace('}', '%7D')

    return filter

#URL path building
def build_url(api_path,config_path,filter=[],type=''):
    """ Takes an api path, config path and filter and returns the full URL along with the UID. """
    url = f'{BASE_URL}{API_ROOT}{api_path}?config_path={config_path}'
    if type != '':
        url += f'&type="{type}"'

    if filter != []:
        url = add_filters_to_url(url,filter)
        
    url = add_uid_to_url(url)
    return url 

def add_filters_to_url(path, filter):
    """ Takes an API path and filter and returns the URL with the filter sanitized and attached to the URL. """
    filter_string = ''
    filter_options = []

    if filter != []:
        filter_string = '[{"' + filter[0] + '":{"' + filter[1] + '":['
        filter_options = filter[2:]
    for filter_option in filter_options:
        #add double quotes around strings otherwise don't
        if type(filter_option) is int:
            filter_string += str(filter_option) + ','
        else:
            filter_string += '"'+filter_option+'",'
    
    #remove last trailing comma
    filter_string = filter_string[:-1]

    filter_string += ']}}]'
    filter_string = sanitize_filter(filter_string)
    path = f'{path}&filter={filter_string}'
    
    return path

def add_uid_to_url(url):
    """ Adds the UIDARUBA to the provided url and returns the final url"""

    if '?' in url:
        url = f'{url}&UIDARUBA={ex_tokens.UIDARUBA}'
    else:
        url = f'{url}?UIDARUBA={ex_tokens.UIDARUBA}'

    return url

def call_api(api_url,config_path=DEFAULT_PATH, data={},filter=[],post=False):
    """ Builds the URL using the API_URL and any other data passed along. """
    URL = build_url(api_url,config_path=config_path,filter=filter)
    if data != {}:
        payload = json.dumps(data)
    if post:
        return make_request(URL,data=payload,post=True)
    else:
        return make_request(URL)

def configure_multiple_objects(config_objects,path=DEFAULT_PATH):
  """ Configure multiple objects. The syntax is:
    { '_list': [ { 'OBJECT1' : [ {'ATTR1':'VALUE'},{'ATTR2':'VALUE'} ], 'OBJECT2': ... """

  API_PATH = ''
  return call_api(API_PATH,config_path=path,data=config_objects,post=True)

#commit or purge pending changes
def write_mem(path=DEFAULT_PATH):
    """ Saves pending configurations under specified path """

    url = build_url('write_memory',config_path=path)
    url = add_uid_to_url(url)

    return make_request(url,post=True)

def purge_pending_config(path=DEFAULT_PATH):
    """ Purges any pending configuration. Body contains:
    {
         "node-path": "string"
    }"""

    URL = build_url('configuration_purge_pending',config_path=path)
    payload = json.dumps({"node-path":path})
    return make_request(URL,data=payload,post=True)

#external document handling
def get_table_titles(document):
    """ Given a word document name, returns an array of table_titles from the document. """
    design_doc = Document(document)

    paragraphs = design_doc.paragraphs
    title_match = re.compile(r'Table \d{1,2} . ((\w+\s?)+)')
    table_titles = []

    for paragraph in paragraphs:
        match = title_match.match(paragraph.text)
        if type(match) is re.Match:
            table_titles.append(match.group(1))

    return table_titles

def extract_row_cells_from_table(table):
  """ Returns an array of row_cells without the header row. """

  table_rows =[]

  enum_table_rows = enumerate(table.rows)

  for count,_ in enum_table_rows:
      table_rows.append(table.row_cells(count))

  return table_rows[1:]

def extract_column_cells_from_table(table):
  """ Returns an array of column_cells without the header column. """

  table_columns = []

  enum_table_cols = enumerate(table.columns)

  for count,_ in enum_table_cols:
    table_columns.append(table.column_cells(count))

  return table_columns[1:]

def get_unique_values_from_cells(table_cells):
    """ Returns a list of sites from the table column provided """
    values = []
    for cell in table_cells:
        if not cell.text in values:
            values.append(cell.text)
    
    return values

def get_column_from_table(column_name,table):
    """ Returns the column defined by column_name in the table. """
    title_row = table.row_cells(0)
    index = 0
    for title in title_row:
        if title.text == column_name:
            return table.column_cells(index)[1:]
        else:
            index += 1
    
    if index == len(table.columns):
        raise ValueError

def build_tables_columns_dict(tables):
  """ Build a dictionary of column_name : column_cells from the tables provided. """

  node_column = None

  for table in tables:
    table_columns = [column for column in table.columns]
    for column in table_columns:
      if column.cells[0].text == 'Node':
        node_column = column.cells[1:]
        table_columns = remove_node_column(table)
        table_columns = add_node_info_to_profile_name(node_column, table_columns)
    
    for column in table_columns:
      if column.cells[0].text not in TABLE_COLUMNS.keys():
        attribute_names = data_structures.COL_TO_ATTR[column.cells[0].text]
        for attribute_name in attribute_names:
          TABLE_COLUMNS[attribute_name] = [sanitize_white_spaces(cell.text) for cell in column.cells[1:]]

def remove_node_column(table):
  """ Removes the node column from the table. """

  table_columns = []
  
  for column in table.columns:
    if column.cells[0].text != 'Node':
      table_columns.append(column)
  
  return table_columns

def add_entries_to_object_identifiers():
  """ Adds a list of entries to the objects identifiers set. """
  for ref in API_REF:
    for object in ref['definitions']:
      if 'required' in ref['definitions'][object]:
        if len(ref['definitions'][object]['required']) == 1:
          OBJECT_IDENTIFIERS[object] = f'{object}.{ref["definitions"][object]["required"][0]}'
        else:
          name_pattern = re.compile(r'.*name$')
          required_props = ref['definitions'][object]['required']
          for required_prop in required_props:
            if name_pattern.match(required_prop) is not None:
              if object not in OBJECT_IDENTIFIERS:
                OBJECT_IDENTIFIERS[object] = f'{object}.{required_prop}'

def add_node_info_to_profile_name(node_column, table_columns):
  """ Adds the node information to the profile names in the table. """
  
  for column in table_columns:
    for attribute in data_structures.COL_TO_ATTR[column.cells[0].text]:
      attribute_name = attribute.split('.')[0]
      if attribute == OBJECT_IDENTIFIERS[attribute_name]:
        for profile,node in zip(column.cells[1:],node_column):
          profile.text += ',' + node.text
  
  return table_columns
  
def build_profiles_dependencies(profiles_to_be_configured):
  """ Look for nested profiles and add entries to the TABLE_COLUMNS dictionary to configure those inner profiles. """

  copy = None

  for profile in profiles_to_be_configured:
    copy = profiles_to_be_configured.copy()
    copy.pop(profile)
    for other_profile in copy:
      if profile_is_an_attribute_of_current_profile(profile,other_profile):
        add_dependency_to_table_columns_dict(profile,other_profile)
        add_dependency_to_profiles_to_be_configured(profile,other_profile,profiles_to_be_configured)

def add_dependency_to_profiles_to_be_configured(current_profile,other_profile,profiles_to_be_configured):
  """ Adds the dynamic profiles to profiles to be configured. """

  profile_name = ''
  other_profile_identifier = get_object_identifier(other_profile)

  if other_profile in data_structures.DEPENDENCY_DICT.keys():
    profile_name = f'{data_structures.DEPENDENCY_DICT[other_profile]}.{other_profile_identifier}'
  else:
    profile_name = f'{other_profile}.{other_profile_identifier}'

  profiles_to_be_configured[current_profile].append(profile_name)  


def profile_is_an_attribute_of_current_profile(current_profile,other_profile):
  """ Returns True if other_profile is an attribute of current_profile. """
  
  current_profile_properties = get_profile_properties(current_profile)

  if other_profile in data_structures.DEPENDENCY_DICT.keys():
    return data_structures.DEPENDENCY_DICT[other_profile] in current_profile_properties
  else:
    return other_profile in current_profile_properties

def add_dependency_to_table_columns_dict(current_profile,other_profile):
  """ Adds entries to the TABLE_COLUMNS dictionary if the two profiles are dependent. """

  current_profile_identifier = OBJECT_IDENTIFIERS[current_profile]
  other_profile_identifier = OBJECT_IDENTIFIERS[other_profile]
  if current_profile != '' and other_profile_identifier != '':
    current_profile_names = TABLE_COLUMNS[current_profile_identifier]
    other_profile_names = TABLE_COLUMNS[other_profile_identifier]
    dynamic_profile_name = ''

    for profile_name in current_profile_names:
      if profile_name in other_profile_names:
        name_without_node_info = profile_name.split(',')[0]
        if other_profile in data_structures.DEPENDENCY_DICT.keys():
          _,identifier = other_profile_identifier.split('.')
          dynamic_profile_name = f'{current_profile}.{data_structures.DEPENDENCY_DICT[other_profile]}.{identifier}'
        else:
          dynamic_profile_name = f'{current_profile}.{other_profile_identifier}'      
        if dynamic_profile_name in TABLE_COLUMNS.keys():
          TABLE_COLUMNS[dynamic_profile_name].append(f'{name_without_node_info}_{other_profile}')
        else:
          TABLE_COLUMNS[dynamic_profile_name] = [f'{name_without_node_info}_{other_profile}'] 

def get_object_identifier(object):
  """ Given an API object, return a possible identifier. If object does not have an identifier, return an empty string. """

  for ref in API_REF:
    if object in ref['definitions']:
      if 'required' in ref['definitions'][object]:
        for possible_identifier in ref['definitions'][object]['required']:
          if 'name' in possible_identifier:
            return possible_identifier
        return ''

def get_profile_properties(profile):
  """ Returns properties of the profile from the API_REF dictionary. """

  for ref in API_REF:
    if profile in ref['definitions']:
      return [prop for prop in ref['definitions'][profile]['properties']]

def get_profiles_to_be_configured():
  """ Get the profiles to be configured from the table keys. The result is a dictionary of profile: [attributes]. """

  profiles_to_configure = {}
  full_name = ''

  for name in TABLE_COLUMNS:
    if len(name.split('.')) < 3:
      name += '.'
    profile_name,attribute,property = name.split('.')
    if property != '':
      full_name = attribute + '.' + property
    else:
      full_name = attribute

    if profile_name in profiles_to_configure.keys():
      profiles_to_configure[profile_name].append(full_name)
    else:
      profiles_to_configure[profile_name] = [full_name]
  
  return profiles_to_configure

def check_that_required_attributes_are_provided(profile_name,profile_attributes,api_json_files):
  """ The profile is a dictionary of prof_name:[attributes]. The profile will be looked up in the API JSON files and the required attributes
      will be checked against the provided attributes. Returns a Boolean. """


  for api_json_file in api_json_files:
    if profile_name in api_json_file["definitions"].keys():
      required_attributes = api_json_file["definitions"][profile_name]["required"]
      for required_attribute in required_attributes:
        if required_attribute not in profile_attributes:
          print(f"You are missing a required attribute for the {profile_name} profile: {required_attribute} must be provided.")
          return False

  return True

def get_object_identifiers():
  """ Crawl through the API and get the required properties for all the objects. Returns a set of possible object identifiers. """

  object_ids = set() 

  for ref in API_REF:
    for ref_object in ref['definitions']:
      if 'required' in ref['definitions'][ref_object]:
        for required_prop in ref['definitions'][ref_object]['required']:
          object_ids.add(required_prop)        
  
  return object_ids

def get_objects_without_required_attributes():
  """ Returns a set of objects without required properties from the API. """

  objects = set()

  for ref in API_REF:
    for ref_object in ref['definitions']:
      if 'required' not in ref['definitions'][ref_object]:
        objects.add(ref_object)
  
  return objects
   
def sanitize_white_spaces(text):
  """ Remove leading/trailing white spaces and replace any carriage returns with spaces. """

  trailing_ws = re.compile(r'(.+) $')
  leading_ws = re.compile(r' (.+)$')

  match_trailing_ws = trailing_ws.match(text)
  if match_trailing_ws is not None:
    text = match_trailing_ws.group(1)
  
  match_leading_ws = leading_ws.match(text)
  if match_leading_ws is not None:
    text = match_leading_ws.group(1)

  text = text.replace('\n',' ')

  return text