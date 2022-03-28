import urllib3
import requests
import json

BASE_URL = ''
DEFAULT_PATH = ''
API_ROOT = 'configuration/object/'

UIDARUBA = ''
X_CSRF_TOKEN = ''

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

    cookies = dict(SESSION = UIDARUBA)
    headers = {'x-csrf-token':X_CSRF_TOKEN}
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
        url = f'{url}&UIDARUBA={UIDARUBA}'
    else:
        url = f'{url}?UIDARUBA={UIDARUBA}'

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