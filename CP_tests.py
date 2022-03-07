import AOS8_Configuration_Picker as CP

def test_build_hierarchy_builds_all_paths():
    """ The build hierarchy function correctly returns all intermediate paths. """

    expected = ['/md/NA','/md/NA/US','/md/NA/US/HQ', '/md/NA/US/HQ/DC']
    generated = CP.build_hierarchy('/NA/US/HQ/DC')

    assert expected == generated