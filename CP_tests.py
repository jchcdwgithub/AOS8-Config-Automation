import AOS8_config_automation as CA
import setup
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