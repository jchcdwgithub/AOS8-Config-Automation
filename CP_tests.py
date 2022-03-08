import AOS8_config_automation as CA
from docx import Document

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