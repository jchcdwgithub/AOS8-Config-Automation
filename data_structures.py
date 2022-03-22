COL_TO_ATTR = {"RF Profile":["ap_g_radio_prof.profile-name","ap_a_radio_prof.profile-name","reg_domain_prof.profile-name"],
               "Device MAC": ["configuration_device.mac-address"],
               "Device Node": ["configuration_device.config-path"],
               "Device Model":["configuration_device.dev-model."],
               "MGMT Int VLAN":['int_mgmt.int_mgmt_ip.vlanid'],
               "MGMT Int IP":['int_mgmt.int_mgmt_ip.ipaddr'],
               "MGMT Int DHCP":['int_mgmt.int_mgmt_dhcp'],
               "MGMT Int Netmask":['int_mgmt.int_mgmt_ip.ipmask'],
               "VLAN ID":['vlan_id.id'],
               "Option 82":['vlan_id.option-82'],
               "VLAN Description":['vlan_id.vlan_id__descr.descr'],
               "PortChannel":['int_pc.id'],
               "PC Interfaces":['int_pc.int_pc_add_gig.slot/module/port'],
               "PC Trunk":['int_pc.int_pc_port_mode.port_mode'],
               "PC Access VLAN":['int_pc.int_pc_access_vlan.vlanId'],
               "PC Allowed VLANs":['int_pc.int_pc_allowed_vlan.WORD'],
               "PC Native VLAN":['int_pc.int_pc_vlan_native.vlanId'],
               "PC Jumbo Frames":['int_pc.int_pc_jumbo'],
               "PC Description":['int_pc.channel_int_desc.LINE'],
               "Loopback Interface":['int_loop.int_loop_ip.ipaddr'],
               "VLAN Name":['vlan_name.name'],
               "VLAN Associated IDs":['vlan_name_id.vlan-ids'],
               "IP Route":['ip_route.destip'],
               "Int VLAN ID":['int_vlan.id'],
               "Int VLAN IP":['int_vlan.int_vlan_ip.ipaddr'],
               "Int VLAN IP Mask":['int_vlan.int_vlan_ip.ipmask'],
               "Int VLAN IP DHCP":['int_vlan.int_vlan_ip.dhcp-client'],
               "Int VLAN IP Helper Address":['int_vlan.int_vlan_ip_helper.address'],
               "NTP Server IP":['ntp_server_info.ip'],
               "NTP Server IPv6":['ntp_server_info.ip6'],
               "NTP Server FQDN":['ntp_server_info.fqdn'],
               "SNMPv2c Server Host IP":['snmp_ser_host_snmpv2c.ipAddress'],
               "SNMPv2c Server Host Community":['snmp_ser_host_snmpv2c.name'],
               "SNMPv2c Server Host Port":['snmp_ser_host_snmpv2c.portnumber'],
               "SNMP Server Community":['snmp_ser_community.name'],
               "DNS Server IPs":['ip_name_server.address'],
               "MC VLAN ID:":['ctrl.id'],
               "MC Loopback:":['ctrl.loopback'],
               "Gig Interface":['int_gig.slot/module/port'],
               "Gig Int Speed":['int_gig.int_gig_speed.port_speed'],
               "Gig Int Duplex":['int_gig.int_gig_duplex.duplex_mode'],
               "Gig Int Description":['int_gig.int_gig_desc.LINE'],
               "Gig Int Mode":['int_gig.int_gig_mode.port_mode'],
               "Gig Int Access VLAN":['int_gig.int_gig_access_vlan.id'],
               "Gig Int Allowed VLANs":['int_gig.int_gig_vlan.WORD'],
               "Gig Int Allow All VLANs":['int_gig.int_gig_vlan_all'],
               "Gig Int Native VLAN":['int_gig.int_gig_vlan_native.id'],
               "Gig Int Jumbo Frames":['int_gig.int_gig_jumbo'],
               "Rad Server Name":['rad_server.rad_server_name'],
               "Rad Server Hostname":['rad_server.rad_host.host'],
               "Rad Server Key":['rad_server.rad_key.key'],
               "Rad Server AuthPort":['rad_server.rad_authport.authport'],
               "Rad Server AcctPort":['rad_server.rad_acctport.acctport'],
               "Dot1X Profile":['dot1x_auth_profile.profile-name'],
               "Server Group":['server_group_prof.sg_name'],
               "SG Server Name":['server_group_prof.auth_server.name'],
               "AAA Profile":['aaa_prof.profile-name'],
               "AAA Default Role":['aaa_prof.default_user_role.role'],
               "AAA Server Derived Role":['aaa_prof.download_role'],
               "AAA RFC3576 IP":['aaa_prof.rfc3576_client.rfc3576_server'],
               "Dot1x Default Role":['aaa_prof.dot1x_default_role.default-role'],
               "AAA Server Group":['aaa_prof.dot1x_server_group.srv-group'],
               "Server Derived Role":['aaa_prof.download_role'],
               "RFC 3576 Servers":['aaa_prof.rfc3576_client.rfc3576_server'],
               "MAC Auth":['mac_auth_profile.profile-name'],
               "Cluster Profile":['cluster_prof.profile-name'],
               "Cluster MC IP":['cluster_prof.cluster_controller.ip'],
               "Cluster MC VRRP IP":['cluster_prof.cluster_controller.vrrp_ip'],
               "Cluster MC VRRP VLAN":['cluster_prof.cluster_controller.vrrp_vlan'],
               "DHCP Pool Name": ['ip_dhcp_pool_cfg.pool_name'],
               "DHCP Pool DNS IP": ['ip_dhcp_pool_cfg.ip_dhcp_pool_cfg__dns.address1'],
               "DHCP Pool Default Router": ['ip_dhcp_pool_cfg.ip_dhcp_pool_cfg__def_rtr.address'],
               "DHCP Pool Subnet": ['ip_dhcp_pool_cfg.ip_dhcp_pool_cfg__net.subnet'],
               "DHCP Pool Subnet Mask": ['ip_dhcp_pool_cfg.ip_dhcp_pool_cfg__net.mask'],
               "DHCP Pool Start Address": ['ip_dhcp_pool_cfg.ip_dhcp_pool_cfg__range.address1'],
               "DHCP Pool End Address": ['ip_dhcp_pool_cfg.ip_dhcp_pool_cfg__range.address2'],
               "DHCP Pool Lease (days)": ['ip_dhcp_pool_cfg.ip_dhcp_pool_cfg__lease.var1'],
               "DHCP Pool Lease (hours)": ['ip_dhcp_pool_cfg.ip_dhcp_pool_cfg__lease.var2'],
               "DHCP Pool Lease (minutes)": ['ip_dhcp_pool_cfg.ip_dhcp_pool_cfg__lease.var3'],
               "Standard ACL": ['acl_std.accname'],
               "Extended ACL": ['acl_ext.accname'],
               "Session ACL": ['acl_sess.accname'],
               "Standard ACEs": ['acl__std.acl_std__v4policy'],
               "Extended ACEs": ['acl__ext.acl_ext__v4policy'],
               "Session ACEs": ['acl__sess.acl_sess__v4policy.ace'],
               "Netdest": ['netdst.dstname'],
               "Netdest Hosts":['netdst.netdst__host.address'],
               "Netdest Network":['netdst.netdst__network.address'],
               "Netdest Network Netmask":['netdst.netdst__network.netmask'],
               "Netdest Network Names":['netdst.netdst__name.host_name'],
               "Role":['role.rname'],
               "Role ACLs":['role.role__acl.pname'],
               "Role VLAN":['role.role__vlan.vlanstr'],
               "Role CP Profile":['role.role__cp.cp_profile_name'],
               "2.4 GHz Minimum": ["ap_g_radio_prof.eirp_min.eirp-min"],
               "2.4 GHz Maximum": ["ap_g_radio_prof.eirp_max.eirp-max"],
               "5 GHz Minimum": ["ap_a_radio_prof.eirp_min.eirp-min"],
               "5 GHz Maximum": ["ap_a_radio_prof.eirp_max.eirp-max"],
               "5 GHz Channel Width": ["reg_domain_prof.channel_width.width"],
               "2.4 GHz Channels": ["reg_domain_prof.valid_11b_channel.valid-11g-channel"],
               "5 GHz Channels": ["reg_domain_prof.valid_11a_channel.valid-11a-channel"],
               "2.4 GHz AM Scan Prof":['ap_g_radio.am_scan_prof.profile-name'],
               "5 GHz AM Scan Prof":['ap_a_radio.am_scan_prof.profile-name'],
               "WLAN ESSID":["ssid_prof.profile-name","ssid_prof.essid.essid","virtual_ap.profile-name"],
               "G Rates Required":["ssid_prof.g_basic_rates"],
               "G Rates Allowed":["ssid_prof.g_tx_rates"],
               "A Rates Required":["ssid_prof.a_basic_rates"],
               "A Rates Allowed":["ssid_prof.a_tx_rates"],
               "AP Group":["ap_group.profile-name"],
               "AP Group 5 GHz Profile":["ap_group.dot11a_prof.profile-name"],
               "Group VAPs":["ap_group.virtual_ap.profile-name"],
               "VAP VLAN Mapping":["virtual_ap.vlan.vlan"],
               "Forwarding Mode":['virtual_ap.forward_mode.forward_mode'],
               "Frequency Bands":['virtual_ap.vap_rf_band.rf_band_tristate'],
               "WMM EAP AC":["ssid_prof.wmm_eap_ac.wmm_ac"],
               "QoS Profile":["wlan_qos_prof.profile-name"],
               "QoS BW Allocation VAP":["wlan_qos_prof.bw_alloc.virtual-ap"],
               "QoS BW Allocation Share":["wlan_qos_prof.bw_alloc.share"],
               "CP Profile":['cp_auth_prof.profile-name'],
               "AUP":['cp_auth_prof.show_aup'],
               "CP Welcome Page":['cp_auth_prof.cp_welcome_location.welcome-page'],
               "CP Login Page":['cp_auth_prof.cp_login_location.login-page'],
               "CP Server Group":['cp_auth_prof.cp_server_group'],
               "CP Default Role":['cp_auth_prof.cp_default_role.cp-default-role'],
               "CP User Logon":['cp_auth_prof.allow_user'],
               "CP Whitelist":['cp_auth_prof.cp_white_list.white-list'],
               "Netdestination":['netdst.dstname'],
               "Netdest Name Entries":['netdst.netdst__name.host_name'],
               "Netdest Network Entries":['netdst.netdst__network.address'],
               "Netdest Host Entries":['netdst.netdst__host.address'],
               "Wired Port Profile":['wired_port.profile-name'],
               "Wired Port AAA Prof":['wired_port.wired_aaa_prof.profile-name'],
               "Wired Port Bridge Role":['wired_port.bridge_role.role'],
               "Wired Port Loop Protect":['wired_port.loop_protect_enable'],
               "AP System Profile":['ap_sys_prof.profile-name'],
               "AP Sys LMS IP":['ap_sys_prof.lms_ip.lms-ip'],
               "AP Sys Bkup LMS IP":['ap_sys_prof.bkup_lms_ip.bkup-lms-ip'],
               "AP Sys AP Console PW":['ap_sys_prof.ap_console_password.ap-console-password'],
               "MFP/PMF":['ssid_prof.mfp_capable'],
               "WLAN OPMODE":['ssid_prof.opmode'],
               "Transition Mode":['ssid_prof.wpa3_transition']
}

BOOLEAN_DICT = {'Beacon':'ba', 'Probe':'pr', 'Low Data': 'ldata', 'High Data': 'hdata', 'Management':'mgmt',
                'Control': 'ctrl', 'All': 'all','True':True, 'False':False, 'Default':'default', 'Best Effort': 'best-effort',
                'Background': 'background', 'Voice': 'voice', 'Video': 'video',
                'WMM EAP AC':'wmm-eap-ac',
                'WPA2-AES':'wpa2-aes',
                'WPA3-SAE-AES':'wpa3-sae-aes',
                'Open':'opensys',
                'Enhanced Open':'enhanced-open',
                'WPA2-AES':'wpa2-aes',
                'WPA2-PSK-AES':'wpa2-psk-aes',
                'Trunk':'trunk',
                'Access':'Access',
                '20 MHz': '20mhz',
                '40 MHz':'40mhz',
                '80 MHz':'80mhz',
                '160 MHz':'160mhz',
                'G Only':'g',
                'A Only':'a',
                'Tunnel':'tunnel',
                'Bridge':'bridge',
                'Split-Tunnel':'split-tunnel',
                'Decrypt-Tunnel':'decrypt-tunnel'}

DEPENDENCY_DICT = {'ap_g_radio_prof':'dot11g_prof', 
                   'ap_a_radio_prof':'dot11a_prof',
                   'server_group':'dot1x_server_group',
                   'acl_sess':'role__acl',
                   'acl_std':'role__acl',
                   'acl_ext': 'role__acl',
                   'ap_group':'loc',
                   'accname':'pname',
                   'aaa_prof':'wired_aaa_prof',
                   'vlan_id':'id',
                   'rad_server':'auth_server',
                   'rad_server_name':'name'
                   }