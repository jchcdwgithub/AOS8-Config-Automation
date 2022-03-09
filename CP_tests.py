from re import fullmatch
import AOS8_config_automation as CA
import setup
import pytest
from docx import Document

API_FILES_TEST = setup.get_API_JSON_files()

def test_build_hierarchy_builds_all_paths():
    """ The build hierarchy function correctly returns all intermediate paths. """

    expected = ['/md/NA','/md/NA/US','/md/NA/US/HQ', '/md/NA/US/HQ/DC']
    generated = CA.build_hierarchy('/NA/US/HQ/DC')

    assert expected == generated

def test_get_columns_from_tables_returns_all_columns():
    """ All the columns in the provided tables should be present in the returned columns dictionary. """

    tables = Document('../Radio Testing Tables.docx').tables

    expected = {"ap_g_radio_prof.profile-name":["CGR","DEP","KFD","PWK","SIG","Test"],
                "ap_a_radio_prof.profile-name":["CGR","DEP","KFD","PWK","SIG","Test"],
                "reg_domain_prof.profile-name":["CGR","DEP","KFD","PWK","SIG","Test"],
                "ap_g_radio_prof.eirp_min":["3 dBm", "3 dBm", "3 dBm", "3 dBm", "3 dBm", "3 dBm"],
                "ap_g_radio_prof.eirp_max":["7 dBm", "7 dBm", "7 dBm", "7 dBm", "7 dBm", "7 dBm"],
                "ap_a_radio_prof.eirp_min":["6 dBm", "6 dBm", "6 dBm", "6 dBm", "6 dBm", "6 dBm"],
                "ap_a_radio_prof.eirp_max":["10 dBm", "10 dBm", "10 dBm", "10 dBm", "10 dBm", "10 dBm"],
                "reg_domain_prof.valid_11b_channels":["1, 6, 11", "1,6,11", "1, 6, 11", "1, 6, 11", "1, 6, 11", "1, 6, 11"],
                "reg_domain_prof.valid_11a_channels":["36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161,165", "36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161,165", "36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161,165", "36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161,165", "36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161,165", "36, 40, 44, 48, 149, 153, 157, 161,165" ],
                "reg_domain_prof.valid_11a_40mhz_chan_nd":["20 MHz", "20 MHz", "20 MHz", "20 MHz", "20 MHz", "80 MHz"],
                "reg_domain_prof.valid_11a_80mhz_chan_nd":["20 MHz", "20 MHz", "20 MHz", "20 MHz", "20 MHz", "80 MHz"],
                "ssid_prof.profile-name":["ChoiceAccess", "CorpAccess", "CorpTest", "GuestAccess", "MobiAccess"],
                "ssid_prof.g_basic_rates":["12", "12", "12", "12", "12"],
                "ssid_prof.g_tx_rates":["12, 18, 24, 36, 48, 54", "12, 18, 24, 36, 48, 54", "12, 18, 24, 36, 48, 54", "12, 18, 24, 36, 48, 54", "12, 18, 24, 36, 48, 54"],
                "ssid_prof.a_basic_rates":["12", "12", "12, 24", "12", "12"],
                "ssid_prof.a_tx_rates":["12, 18, 24, 36, 48, 54", "12, 18, 24, 36, 48, 54", "12, 18, 24, 36, 48, 54", "12, 18, 24, 36, 48, 54", "12, 18, 24, 36, 48, 54"]}
    
    generated = CA.get_columns_from_tables(tables)

    assert expected == generated

def test_get_profiles_to_be_configured_returns_correct_dictionary():
    """ Given the above test tables, get the names and attributes of profiles to be configured. """

    tables = Document('../Radio Testing Tables.docx').tables
    attributes = CA.get_columns_from_tables(tables)

    expected = {"ap_g_radio_prof":["profile-name","eirp_min","eirp_max"],
                "ap_a_radio_prof":["profile-name","eirp_min","eirp_max"],
                "reg_domain_prof":["profile-name","valid_11b_channels","valid_11a_channels","valid_11a_40mhz_chan_nd","valid_11a_80mhz_chan_nd"],
                "ssid_prof":["profile-name","g_basic_rates","g_tx_rates","a_basic_rates","a_tx_rates"]}
    
    generated = CA.get_profiles_to_be_configured(attributes)

    assert expected == generated

def test_check_for_required_attributes_returns_true_when_all_attributes_are_configured():

    profile_name = "configuration_device_filename"
    profile_attributes = [
                "dev-model",
                "config-path",
                "mac-address",
                "filename"
            ]
    
    Result = CA.check_that_required_attributes_are_provided(profile_name,profile_attributes,API_FILES_TEST)

    assert Result == True

def test_check_for_required_attributes_returns_false_when_attributes_are_missing():

    profile_name = 'configuration_device_filename'
    profile_attributes = [
                "dev-model",
                "mac-address",
                "filename"
            ]

    Result = CA.check_that_required_attributes_are_provided(profile_name,profile_attributes,API_FILES_TEST)

    assert Result == False

def test_is_nested_profile_returns_true_for_internal_profile():

    attribute_name = "aaa_prof"

    Result = CA.is_nested_profile(attribute_name)

    assert Result == True

def test_is_nested_profile_returns_false_for_other_attribute_names():

    attribute_name = "eirp_max"

    Result = CA.is_nested_profile(attribute_name)

    assert Result == False

def test_get_attribute_type_returns_the_correct_integer_type():

    full_attribute_name = "foreign_agent_general_prof_it.interval-time"

    expected = "integer"

    generated = CA.get_attribute_type(full_attribute_name)

    assert expected == generated

def test_get_attribute_type_returns_the_correct_string_type():

    full_attribute_name = "ssid_prof.profile-name"

    expected = "string"

    generated = CA.get_attribute_type(full_attribute_name)

    assert expected == generated

def test_get_object_property_name_returns_a_list_of_names():

    full_attribute_name = "ap_mesh_radio_prof.mesh_a_tx_rates"

    expected = ["6", "9", "12", "18", "24", "36", "48", "54"]

    generated = CA.get_object_property_name(full_attribute_name)

    assert expected == generated

def test_is_enum_returns_true_for_enumerated_properties():

    profile_name = "anqp_nwk_auth_prof"
    attribute_name = "anqp_nwk_auth_type"
    property_name = CA.get_object_property_name(profile_name+'.'+attribute_name)[0]

    Result = CA.is_enumerated_property(profile_name,attribute_name,property_name)

    assert Result == True

def test_is_enum_returns_false_for_other_properties():

    profile_name = "virtual_ap"
    attribute_name = "aaa_prof"
    property_name = "profile-name"

    Result = CA.is_enumerated_property(profile_name,attribute_name,property_name)

def test_string_is_in_enumerated_properties_list_returns_true_for_strings_in_list():

    profile_name = "anqp_nwk_auth_prof"
    attribute_name = "anqp_nwk_auth_type"
    property_name = "anqp_nwk_auth_type"
    test_string = "http-https-redirection"

    Result = CA.string_is_in_enumerated_property_list(profile_name,attribute_name,property_name,test_string)

    assert Result == True 

def test_string_is_in_enumerated_properties_list_returns_false_for_strings_not_in_list():

    profile_name = "anqp_nwk_auth_prof"
    attribute_name = "anqp_nwk_auth_type"
    property_name = "anqp_nwk_auth_type"
    test_string = "aruba-central"

    Result = CA.string_is_in_enumerated_property_list(profile_name,attribute_name,property_name,test_string)

    assert Result == False

def test_get_attribute_min_len_returns_correct_minimum_number_for_non_nested_string():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "profile-name"
    
    expected = 1

    generated = CA.get_attribute_min_len(profile_name,attribute_name)

    assert expected == generated

def test_get_attribute_max_len_returns_correct_maximum_number_for_non_nested_string():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "profile-name"
    
    expected = 256

    generated = CA.get_attribute_max_len(profile_name,attribute_name)

    assert expected == generated

def test_get_attribute_min_len_returns_correct_minimum_number_for_nested_string():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "mesh_allowed_vlans"
    property_name = "vlan-list"
    
    expected = 1

    generated = CA.get_attribute_min_len(profile_name,attribute_name,property_name)

    assert expected == generated

def test_get_attribute_max_len_returns_correct_maximum_number_for_nested_string():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "mesh_allowed_vlans"
    property_name = "vlan-list"
    
    expected = 256

    generated = CA.get_attribute_max_len(profile_name,attribute_name,property_name)

    assert expected == generated

def test_is_valid_string_returns_true_for_string_length_check():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "profile-name"
    string = "some_profile_name"

    Result = CA.is_valid_string_or_number(profile_name,attribute_name,string)

    assert Result == True

def test_is_valid_string_returns_false_for_null_string_length_check():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "profile-name"
    string = ""

    Result = CA.is_valid_string_or_number(profile_name,attribute_name,string)

    assert Result == False

def test_is_valid_string_returns_false_for_too_long_string_length_check():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "profile-name"
    string = "a"*257

    Result = CA.is_valid_string_or_number(profile_name,attribute_name,string)

    assert Result == False

def test_is_valid_string_returns_true_for_nested_string_length_check():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "mesh_allowed_vlans"
    property_name = "vlan-list"
    string = "WIRELESS"

    Result = CA.is_valid_string_or_number(profile_name,attribute_name,string,property_name=property_name)

    assert Result == True

def test_is_valid_string_returns_false_for_null_nested_string_length_check():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "mesh_allowed_vlans"
    property_name = "vlan-list"
    string = ""

    Result = CA.is_valid_string_or_number(profile_name,attribute_name,string,property_name=property_name)

    assert Result == False

def test_is_valid_string_returns_false_for_too_long_nested_string_length_check():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "mesh_allowed_vlans"
    property_name = "vlan-list"
    string = "a"*257

    Result = CA.is_valid_string_or_number(profile_name,attribute_name,string,property_name=property_name)

    assert Result == False

def test_get_required_properties_returns_expected_required_list_when_it_exists():

    profile_name = "ids_signature_prof"
    attribute_name = "ids_condition_frame_type"

    expected = [
                        "control",
                        "deauth",
                        "frame_type_w_ssid",
                        "auth",
                        "assoc",
                        "disassoc",
                        "mgmt",
                        "data"
                    ]
    
    generated = CA.get_required_properties(profile_name,attribute_name)

    for item in expected:
        assert item in generated

def test_get_required_properties_returns_empty_required_list_when_it_doesnt_exist():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "mesh_a_tx_rates"
    
    generated = CA.get_required_properties(profile_name,attribute_name)

    assert len(generated) == 0

def test_property_is_in_properties_returns_true_for_a_existing_property():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "mesh_a_tx_rates"

    Result = CA.property_is_in_properties(profile_name,attribute_name,'6')

    assert Result == True

def test_property_is_in_properties_returns_false_for_a_nonexisting_property():

    profile_name = "ap_mesh_radio_prof"
    attribute_name = "mesh_a_tx_rates"

    Result = CA.property_is_in_properties(profile_name,attribute_name,'127')

    assert Result == False

def test_is_valid_string_or_number_returns_true_for_number_in_bound():

    profile_name = "ap_g_radio_prof"
    attribute_name = "max_distance"
    property_name = "maximum-distance"

    Result = CA.is_valid_string_or_number(profile_name,attribute_name,100,property_name=property_name,type="integer")

    assert Result == True

def test_is_valid_string_or_number_returns_false_for_number_too_big():

    profile_name = "ap_g_radio_prof"
    attribute_name = "max_distance"
    property_name = "maximum-distance"

    Result = CA.is_valid_string_or_number(profile_name,attribute_name,1000000,property_name=property_name,type="integer")

    assert Result == False

def test_is_valid_string_or_number_returns_false_for_number_too_small():

    profile_name = "ap_g_radio_prof"
    attribute_name = "max_distance"
    property_name = "maximum-distance"

    Result = CA.is_valid_string_or_number(profile_name,attribute_name,-1,property_name=property_name,type="integer")

    assert Result == False

def test_add_integer_attributes_to_profiles_correctly_adds_attributes_to_profiles():

    full_attribute_name = 'ap_multizone_prof.controller.num_vaps'

    profiles = [{'controller': {}}]

    attributes = ['15']

    expected = 15
    CA.add_integer_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert expected == profiles[0]['controller']['num_vaps']

def test_add_string_attributes_to_profiles_correctly_adds_attributes_to_profiles():

    full_attribute_name = 'ap_multizone_prof.profile-name'

    profiles = [{}]
    attributes = ['test_ap_multizone_prof']

    CA.add_string_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert 'test_ap_multizone_prof' == profiles[0]['profile-name']

def test_add_string_attribute_to_profiles_correctly_adds_nested_strings():

    full_attribute_name = 'ap_multizone_prof.ap_multizone_prof_clone.source'

    profiles = [{'ap_multizone_prof_clone':{}}]
    attributes = ['test_ap_multizone_prof']

    CA.add_string_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert 'test_ap_multizone_prof' == profiles[0]['ap_multizone_prof_clone']['source']

def test_add_boolean_attribute_to_profiles_correctly_adds_attribute():

    full_attribute_name = 'airmatch_ap_unfreeze.all-aps'

    profiles = [{}]
    attributes = ['True']

    CA.add_boolean_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert True == profiles[0]['all-aps']

def test_add_boolean_attribute_to_profiles_correctly_adds_nested_boolean_attribute():

    full_attribute_name = 'ssid_prof.opmode.wpa3-sae-aes'

    profiles = [{'opmode':{}}]
    attributes = ['True']

    CA.add_boolean_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert True == profiles[0]['opmode']['wpa3-sae-aes']

def test_add_object_attribute_to_profiles_correctly_adds_an_empty_object_attribute():

    full_attribute_name = 'ssid_prof.enable_ssid'

    profiles = [{}]
    attributes = ['True']

    CA.add_object_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert {} == profiles[0]['enable_ssid']

def test_add_object_attribute_to_profiles_correctly_adds_an_enumerated_string_correctly():

    full_attribute_name = 'ap_mesh_radio_prof.metric_algorithm'

    profiles = [{}]
    attributes = ['best-link-rssi']

    CA.add_object_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert 'best-link-rssi' == profiles[0]['metric_algorithm']['metric_algorithm_enum']

def test_add_object_attribute_to_profiles_raises_error_if_string_is_not_in_enumerated_list():

    full_attribute_name = 'ap_mesh_radio_prof.metric_algorithm'

    profiles = [{}]
    attributes = ['dankest-link-rssi']

    with pytest.raises(ValueError):
        CA.add_object_attribute_to_profiles(full_attribute_name,attributes,profiles)

def test_add_object_attribute_to_profiles_adds_string_to_object_attribute():

    full_attribute_name = "anqp_nwk_auth_prof.anqp_redirect_url"

    profiles = [{}]
    attributes = ['https://www.google.com']

    CA.add_object_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert 'https://www.google.com' == profiles[0]['anqp_redirect_url']['url']

def test_get_attribute_properties_returns_list_of_properties():

    full_attribute_name = "ap_mesh_radio_prof.mesh_a_tx_rates"

    expected = ['6','9','12','18','24','36','48','54']
    generated = CA.get_attribute_properties(full_attribute_name)

    assert expected == generated

def test_get_attribute_properties_returns_empty_list_for_attributes_without_properties():

    full_attribute_name = "ap_mesh_radio_prof.mesh_mcast_opt"

    expected = []
    generated = CA.get_attribute_properties(full_attribute_name)

    assert expected == generated

def test_add_object_attributes_to_profiles_adds_boolean_objects_correctly():

    full_attribute_name = "ids_general_prof.frame_types_for_rssi"

    profiles = [{}]
    attributes = ['Beacon,Probe,Management,Control']

    CA.add_object_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert {'ba':True,'pr':True,'mgmt':True,'ctrl':True} == profiles[0]['frame_types_for_rssi']

def test_add_object_attributes_to_profiles_adds_integer_boolean_objects_correctly():

    full_attribute_name = "ssid_prof.a_basic_rates"

    profiles = [{}]
    attributes = ['6,12,18,24,36']

    CA.add_object_attribute_to_profiles(full_attribute_name,attributes,profiles)

    assert {'6':True,'12':True,'18':True,'24':True,'36':True}

def test_add_object_attributes_to_profiles_raises_value_error_when_boolean_not_defined():

    full_attribute_name = "ids_general_prof.frame_types_for_rssi"

    profiles = [{}]
    attributes = ['Beacon,Probes,Management,Control']
    with pytest.raises(ValueError):
        CA.add_object_attribute_to_profiles(full_attribute_name,attributes,profiles)