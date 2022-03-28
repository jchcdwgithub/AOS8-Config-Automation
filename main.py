import argparse
import api
import AOS8_config_automation as CA
from docx import Document

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--username',help='username for logging into the MCr.')
    parser.add_argument('-p','--password',help='password for logging into the MCr.')
    parser.add_argument('-a','--address',help='IP address of the MCr.')
    parser.add_argument('-n', '--node', help='default configuration node. If not specified, default node will be /md')
    parser.add_argument('-f','--file',help='path to the file of configuration tables.')
    args = parser.parse_args()

    if not args.username is None:
        username = args.username
    else:
        username = input('Username: ')
    
    if not args.password is None:
        password = args.password
    else:
        password = input('Password: ')
    
    if not args.address is None:
        address = args.address
    else:
        address_valid = False
        address = ''
        while(not address_valid):
            address = input('Mobility Conductor IP: ')
            if not CA.is_valid_ip_address(address):
                print('Invalid IP address.')
            else:
                address_valid = True
    
    if not args.node is None:
        api.DEFAULT_PATH = args.node
    else:
        print('Default node not set.')
        set_default_node = input('Set default node value? (y/n)')
        if set_default_node == 'y':
            api.DEFAULT_PATH = input('Default node: ')
        else:
            print('Setting default node to the hierarchy root (/md)...')
            api.DEFAULT_PATH = '/md'
    
    login_success = False
    while(not login_success):
        api.BASE_URL = f"https://{address}:4343/v1/"
        sec_tokens = api.get_security_tokens(username,password)
        if 'UIDARUBA' not in sec_tokens:
            print('Failed to login. Check username and password.')
            username = input('Username: ')
            password = input('Password: ')
        else:
            login_success = True

    api.UIDARUBA = sec_tokens['UIDARUBA']
    api.X_CSRF_TOKEN = sec_tokens['X-CSRF-TOKEN']

    if not args.file is None:
        filename = args.file
    else:
        filename = input('File: ')
    
    CA.add_entries_to_object_identifiers()
    CA.validate_COL_TO_ATTR_dict()
    CA.inventory_devices_in_network()

    file_valid = False
    while(not file_valid):
        try:
            with open(filename) as configuration_doc:
                tables = Document(configuration_doc).tables
                CA.build_tables_columns_dict(tables)
                file_valid = True
        except (FileExistsError,FileNotFoundError):
            print('Invalid file or path to file.')
            input('File: ')
    
    
    errors = CA.get_column_errors()
    print('Potential errors in configuration tables:')
    for error in errors:
        print(error)
    
    abort = input('Fix errors? Program will exit. (y/n)')
    if abort == 'y':
        print('Exiting...')
        exit()

    CA.remove_column_headers_from_columns_table()
    CA.add_mac_auth_info_to_tables_columns()
    CA.add_dot1x_profile_attributes()
    profiles = CA.get_profiles_to_be_configured()
    CA.build_profiles_dependencies(profiles)
    generated = CA.make_ordered_config_list(profiles)
    built_profiles = CA.build_profiles_from_ordered_list(generated)
    api_endpoints = CA.get_list_of_api_endpoints(generated)
    CA.push_profiles_to_network(api_endpoints,built_profiles)
    api.logout()

if __name__ == '__main__':
    main()