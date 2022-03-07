import AOS8_config_automation as CA
from docx import Document

def test_build_hierarchy_builds_all_paths():
    """ The build hierarchy function correctly returns all intermediate paths. """

    expected = ['/md/NA','/md/NA/US','/md/NA/US/HQ', '/md/NA/US/HQ/DC']
    generated = CA.build_hierarchy('/NA/US/HQ/DC')

    assert expected == generated

def test_get_columns_from_tables_returns_all_columns():
    """ All the columns in the provided tables should be present in the returned columns dictionary. """

    tables = Document('../Test Tables.docx').tables[:2]

    expected = {'Device':['Mobility Conductor', 'Mobility Conductory', 'Mobility Controller', 'Mobility Controller'],
                'System Name':['MM-HQ-01','MM-HQ-02','WC-HQ-01','WC-HQ-02'],
                'Part Number':['MM-VA-500','MM-VA-500','A7010','A7010'],
                'MAC':['AA:BB:CC:DD:EE:FF','AA:BB:CC:DD:EE:FF','AA:BB:CC:DD:EE:FF','AA:BB:CC:DD:EE:FF'],
                'Node':['mm','mm','/md/HQ/DC','/md/HQ/DC'],
                'Device Name':['MM-HQ-01','MM-HQ-02','WC-HQ-01','WC-HQ-02'],
                'Interface':['Gi 0/0/0', 'Gi 0/0/0', 'Gi 0/0/5', 'Gi 0/0/5'],
                'Description':['VMSwitch Connection','VMSwitch Connection','HQ 5412 CenterU2 port K4','HQ 5412 CenterU2 port K4'],
                'Trunk':['Trunk','Trunk','Trunk','Trunk'],
                'Native/Access VLAN':['12','12','12','12'],
                'Trunk Allowed VLAN':['All','All','All','All']}
    
    generated = CA.get_columns_from_tables(tables)

    assert expected == generated