import requests
import ex_tokens 
import json
import re
import urllib3
from docx import Document
from pprint import pprint

CONTROLLER_IP = '192.168.1.241'
BASE_URL = f"https://{CONTROLLER_IP}:4343/v1/"
DEFAULT_PATH = '/mm/mynode'
API_ROOT = 'configuration/object/'

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