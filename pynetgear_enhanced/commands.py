# encoding: utf-8
"""Dict of COMMANDS."""
# clArg: [function, help, args:{
#           shortCommand, LongCommand, choices
#           store_true, help
#        }]

COMMANDS = {
    # ---------------------
    # SERVICE_DEVICE_CONFIG
    # ---------------------
    'login': ['login', 'Attempts to login to router'],
    'reboot': ['reboot', 'Reboot Router', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'check_fw': ['check_new_firmware', 'Check for new firmware', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
            }
    ],
    # GET
    'check_app_fw': ['check_app_new_firmware', 'Check app for new firmware', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
            }
    ],
    # GET
    'get_device_config_info': [
        'get_device_config_info', 'Get Device Config Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
            }
    ],
    # **SET**
    'enable_block_device': [
        'set_block_device_enable', 'Enable Access Control', {
            'enable': [
                '-e', '--enable', False,
                'store_true', 'This switch will enable, without will disable'],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'block_device_status': [
        'get_block_device_enable_status', 'Get Access Control Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # **SET**
    'block_device_cli': [
        'set_block_device_by_mac', 'Allow/Block Device by MAC', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
            'mac': [
                '-m', '--mac', False,
                False, 'MAC Address to Allow/Block'],
            'action': [
                '-a', '--action', ['allow', 'block'],
                False, 'Action to take, Allow or Block'],
        }
    ],
    # **SET**
    'enable_traffic_meter': [
        'enable_traffic_meter', 'Enable/Disable Traffic Meter',
        {
            'enable': [
                '-e', '--enable', False,
                'store_true', 'This switch will enable, without will disable'],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'traffic_meter': [
        'get_traffic_meter_statistics', 'Get Traffic Meter Statistics', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'traffic_meter_enabled': [
        'get_traffic_meter_enabled', 'Get Traffic Meter Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'traffic_meter_options': [
        'get_traffic_meter_options', 'Get Traffic Meter Options', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # ---------------------
    # SERVICE_LAN_CONFIG_SECURITY
    # ---------------------
    # GET
    'get_lan_config_info': [
        'get_lan_config_sec_info', 'Get LAN Config Sec Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
            }
    ],
    # ---------------------
    # SERVICE_WAN_IP_CONNECTION
    # ---------------------
    # GET
    'get_wan_ip_info': ['get_wan_ip_con_info', 'Get WAN IP Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
            }
    ],
    # ---------------------
    # SERVICE_PARENTAL_CONTROL
    # ---------------------
    # **SET**
    'enable_parental_control': [
        'enable_parental_control', 'Enable/Disable Parental Control',
        {
            'enable': [
                '-e', '--enable', False,
                'store_true', 'This switch will enable, without will disable'],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'parental_control_status': [
        'get_parental_control_enable_status', 'Get Parental Control Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'mac_address': [
        'get_all_mac_addresses', 'Get all MAC Addresses', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'dns_masq': [
        'get_dns_masq_device_id', 'Get DNS Masq Device ID', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # ---------------------
    # SERVICE_DEVICE_INFO
    # ---------------------
    # GET
    'info': [
        'get_info', 'Get Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'support_feature': [
        'get_support_feature_list_XML', 'Get Supported Features', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'attached_devices': [
        'get_attached_devices', 'Get Attached Devices', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
            'verbose': [
                '-v', '--verbose', False,
                'store_true', 'This switch will enable, without will disable'],
        }
    ],
    # GET
    'attached_devices2': [
        'get_attached_devices_2', 'Get Attached Devices 2', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # ---------------------
    # SERVICE_ADVANCED_QOS
    # ---------------------
    # **SET**
    'speed_test_start': [
        'set_speed_test_start', 'Start Speed Test', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'speed_test_result': [
        'get_speed_test_result', 'Get Speed Test Results', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'qos_enabled': [
        'get_qos_enable_status', 'Get QOS Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # **SET**
    'emable_qos': [
        'set_qos_enable_status', 'Enable/Disable QOS',
        {
            'enable': [
                '-e', '--enable', False,
                'store_true', 'This switch will enable, without will disable'],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'bw_control': [
        'get_bandwidth_control_options', 'Get Bandwidth Control Options',
        {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # ---------------------
    # SERVICE_WLAN_CONFIGURATION
    # ---------------------
    # **SET**
    'guest_access_enable': [
        'set_guest_access_enabled', 'Enable/Disable Guest 2.4G Wifi',
        {
            'enable': [
                '-e', '--enable', False,
                'store_true', 'This switch will enable, without will disable'],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # **SET**
    'guest_access_enable2': [
        'set_guest_access_enabled_2', 'Enable/Disable Guest 2.4G Wifi',
        {
            'enable': [
                '-e', '--enable', False,
                'store_true', 'This switch will enable, without will disable'],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'guest_access': [
        'get_guest_access_enabled', 'Get 2G Guest Wifi Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # **SET**
    'guest_access_enable_5g': [
        'set_5g_guest_access_enabled', 'Enable/Disable Guest 5G Wifi',
        {
            'enable': [
                '-e', '--enable', False,
                'store_true', False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # **SET**
    'guest_access_enable_5g_2': [
        'set_5g_guest_access_enabled_2', 'Enable/Disable Guest 5G Wifi',
        {
            'enable': [
                '-e', '--enable', False,
                'store_true', False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # **SET**
    'guest_access_enable_5g_3': [
        'set_5g_guest_access_enabled_3', 'Enable/Disable Guest 5G Wifi',
        {
            'enable': [
                '-e', '--enable', False,
                'store_true', False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'guest_access_5g': [
        'get_5g_guest_access_enabled', 'Get 5G Guest Wifi Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'wpa_key': [
        'get_wpa_security_keys', 'Get 2G WPA Key', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'wpa_key_5g': [
        'get_5g_wpa_security_keys', 'Get 5G WPA Key', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'get_2g_info': [
        'get_2g_info', 'Get 2G Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'get_5g_info': [
        'get_5g_info', 'Get 5G Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'get_channel': [
        'get_available_channel', 'Get Channel', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'guest_access_net': [
        'get_guest_access_network_info', 'Get 2G Guest Wifi Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'guest_access_net_5g': [
        'get_5g_guest_access_network_info', 'Get 5G Guest Wifi Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # GET
    'get_smart_conn': ['get_smart_connect_enabled', 'Get Smart Conn Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
            }
    ],
    # **SET**
    'set_smart_conn': [
        'set_smart_connect_enabled', 'Enable/Disable Smart Connect',
        {
            'enable': [
                '-e', '--enable', False,
                'store_true', False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
}
