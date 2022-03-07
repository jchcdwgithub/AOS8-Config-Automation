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

    expected = {'Device':['Mobility Conductor', 'Mobility Conductor', 'Mobility Controller', 'Mobility Controller'],
                'System Name':['MM-HQ-01','MM-HQ-02','WC-HQ-01','WC-HQ-02'],
                'Part Number':['MM-VA-500','MM-VA-500','A7010','A7010'],
                'MAC':['AA:BB:CC:DD:EE:FF','AA:BB:CC:DD:EE:FF','AA:BB:CC:DD:EE:FF','AA:BB:CC:DD:EE:FF'],
                'Node':['mm','mm','/md/HQ/DC','/md/HQ/DC'],
                'MM/MC':['MM-HQ-01','MM-SMIT-01','WC-HQ-01','WC-HQ-02'],
                'MGMT IP':['10.0.30.125', '10.0.30.126', '10.0.30.120', '10.0.30.122'],
                'Cluster IP':['10.0.30.127','10.0.30.127','10.0.30.121','10.0.30.123'],
                'AP Discovery':['N/A','N/A','10.0.30.124','10.0.30.124']}
    
    generated = CA.get_columns_from_tables(tables)

    assert expected == generated