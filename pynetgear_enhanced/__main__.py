# encoding: utf-8
"""Run PyNetgear from the command-line."""
from . import NetgearEnhanced  # noqa
import argparse
import time


def main():  # noqa
    """Scan for devices and print results."""

    parser = argparse.ArgumentParser(description='ADD YOUR DESCRIPTION HERE')
    parser.add_argument(
        '-p', '--password', help='Your Password', required=True)
    parser.add_argument(
        '-t', '--test', help='Display response text',
        required=False, action='store_true')
    # ---------------------
    # SERVICE_DEVICE_CONFIG
    # ---------------------
    parser.add_argument(
        '--check_fw', help='Check for new firmware',
        required=False, action='store_true')
    parser.add_argument(
        '--enable_block_device', help='Enable Access Control: '
        'true|false', required=False)
    parser.add_argument(
        '--block_device_status', help='Get Access Control Status',
        required=False, action='store_true')
    parser.add_argument(
        '--enable_traffic_meter', help='Enable Traffic Meter: '
        'true|false', required=False)
    parser.add_argument(
        '--traffic_meter', help='Get Traffic Meter Statistics',
        required=False, action='store_true')
    parser.add_argument(
        '--traffic_meter_enabled', help='Get Traffic Meter Status',
        required=False, action='store_true')
    parser.add_argument(
        '--traffic_meter_options', help='Get Traffic Meter Options',
        required=False, action='store_true')
    # ---------------------
    # SERVICE_PARENTAL_CONTROL
    # ---------------------
    parser.add_argument(
        '--enable_parental_control', help='Enable Parental Control: '
        'true|false', required=False)
    parser.add_argument(
        '--parental_control_status', help='Get Parental Control Status',
        required=False, action='store_true')
    parser.add_argument(
        '--mac_address', help='Get all MAC Addresses',
        required=False, action='store_true')
    parser.add_argument(
        '--dns_masq', help='Get DNS Masq Device ID',
        required=False, action='store_true')
    # ---------------------
    # SERVICE_DEVICE_INFO
    # ---------------------
    parser.add_argument(
        '--info', help='Get Info',
        required=False, action='store_true')
    parser.add_argument(
        '--support_feature', help='Get Supported Features',
        required=False, action='store_true')
    parser.add_argument(
        '--attached_devices', help='Get Attached Devices',
        required=False, action='store_true')
    parser.add_argument(
        '--attached_devices2', help='Get Attached Devices 2',
        required=False, action='store_true')
    # ---------------------
    # SERVICE_ADVANCED_QOS
    # ---------------------
    parser.add_argument(
        '--speed_test_start', help='Start Speed Test',
        required=False, action='store_true')
    parser.add_argument(
        '--speed_test_result', help='Get Speed Test Results',
        required=False, action='store_true')
    parser.add_argument(
        '--enable_qos', help='Enable QOS: '
        'true|false', required=False)
    parser.add_argument(
        '--qos_enabled', help='Get QOS Status',
        required=False, action='store_true')
    parser.add_argument(
        '--bw_control', help='Get Bandwidth Control Options',
        required=False, action='store_true')
    # ---------------------
    # SERVICE_WLAN_CONFIGURATION
    # ---------------------
    parser.add_argument(
        '--guest_access_enable', help='Enable Guest 2.4G Wifi: '
        'true|false', required=False)
    parser.add_argument(
        '--guest_access', help='Get 2G Guest Wifi Status',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access_enable2', help='Enable Guest 2.4G Wifi: '
        'true|false', required=False)
    # parser.add_argument(
    #    '--guest_access2', help='get_guest_access_enabled2',
    #    required=False, action='store_true')
    parser.add_argument(
        '--guest_access_enable_5g', help='Enable Guest 5G Wifi: '
        'true|false', required=False)
    parser.add_argument(
        '--guest_access_5g', help='Get 5G Guest Wifi Status',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access_enable_5g1', help='Enable Guest 5G Wifi2: '
        'true|false', required=False)
    # parser.add_argument(
    #    '--guest_access_5g1', help='get_5g1_guest_access_enabled_2',
    #    required=False, action='store_true')
    parser.add_argument(
        '--guest_access_enable_5g2', help='Enable Guest 5G Wifi3: '
        'true|false', required=False)
    # parser.add_argument(
    #    '--guest_access_5g2', help='get_5g_guest_access_enabled_2',
    #    required=False, action='store_true')
    parser.add_argument(
        '--wpa_key', help='Get 2G WPA Key',
        required=False, action='store_true')
    parser.add_argument(
        '--wpa_key_5g', help='Get 5G WPA Key',
        required=False, action='store_true')
    parser.add_argument(
        '--get_2g_info', help='Get 2G Info',
        required=False, action='store_true')
    parser.add_argument(
        '--get_5g_info', help='Get 5G Info',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access_net', help='Get 2G Guest Wifi Info',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access_net_5g', help='Get 5G Guest Wifi Info',
        required=False, action='store_true')

    args = parser.parse_args()

    if args.password:
        netgear = NetgearEnhanced(args.password)
    # ---------------------
    # SERVICE_DEVICE_CONFIG
    # ---------------------
    if args.check_fw:
        print(netgear.check_new_firmware(args.test))
    if args.enable_block_device:
        print(netgear.set_block_device_enable(
            args.enable_block_device, args.test))
    if args.block_device_status:
        print(netgear.get_block_device_enable_status(args.test))
    if args.traffic_meter:
        print(netgear.get_traffic_meter_statistics(args.test))
    if args.enable_traffic_meter:
        print(netgear.enable_traffic_meter(
            args.enable_traffic_meter, args.test))
    if args.traffic_meter_enabled:
        print(netgear.get_traffic_meter_enabled(args.test))
    if args.traffic_meter_options:
        print(netgear.get_traffic_meter_options(args.test))
    # ---------------------
    # SERVICE_PARENTAL_CONTROL
    # ---------------------
    if args.enable_parental_control:
        print(netgear.enable_parental_control(
            args.enable_parental_control, args.test))
    if args.parental_control_status:
        print(netgear.get_parental_control_enable_status(args.test))
    if args.mac_address:
        print(netgear.get_all_mac_addresses(args.test))
    if args.dns_masq:
        print(netgear.get_dns_masq_device_id(args.test))
    # ---------------------
    # SERVICE_DEVICE_INFO
    # ---------------------
    if args.info:
        print(netgear.get_info(args.test))
    if args.support_feature:
        print(netgear.get_support_feature_list_XML(args.test))
    if args.attached_devices:
        print(netgear.get_attached_devices(args.test))
    if args.attached_devices2:
        print(netgear.get_attached_devices_2(args.test))
    # ---------------------
    # SERVICE_ADVANCED_QOS
    # ---------------------
    if args.speed_test_start:
        print(netgear.set_speed_test_start(args.test))
        time.sleep(30)
        print(netgear.get_speed_test_result(args.test))
    if args.speed_test_result:
        print(netgear.get_speed_test_result(args.test))
    if args.enable_qos:
        print(netgear.set_qos_enable_status(
            args.enable_qos, args.test))
    if args.qos_enabled:
        print(netgear.get_qos_enable_status(args.test))
    if args.bw_control:
        print(netgear.get_bandwidth_control_options(args.test))
    # ---------------------
    # SERVICE_WLAN_CONFIGURATION
    # ---------------------
    if args.guest_access_enable:
        print(netgear.set_guest_access_enabled(
            args.guest_access_enable, args.test))
    if args.guest_access:
        print(netgear.get_guest_access_enabled(args.test))
    if args.guest_access_enable2:
        print(netgear.set_guest_access_enabled_2(
            args.guest_access_enable_2, args.test))
    # if args.guest_access2:
    #    print(netgear.get_guest_access_enabled2(args.test))
    if args.guest_access_enable_5g:
        print(netgear.set_5g_guest_access_enabled(
            args.guest_access_enable_5g, args.test))
    if args.guest_access_5g:
        print(netgear.get_5g_guest_access_enabled(args.test))
    if args.guest_access_enable_5g1:
        print(netgear.set_5g_guest_access_enabled_2(
            args.guest_access_enable_5g1, args.test))
    # if args.guest_access_5g1:
    #    print(netgear.get_5g1_guest_access_enabled_2(args.test))
    if args.guest_access_enable_5g2:
        print(netgear.set_5g1_guest_access_enabled_2(
            args.guest_access_enable_5g2, args.test))
    # if args.guest_access_5g2:
    #    print(netgear.get_5g_guest_access_enabled_2(args.test))
    if args.wpa_key:
        print(netgear.get_wpa_security_keys(args.test))
    if args.wpa_key_5g:
        print(netgear.get_5g_wpa_security_keys(args.test))
    if args.get_2g_info:
        print(netgear.get_2g_info(args.test))
    if args.get_5g_info:
        print(netgear.get_5g_info(args.test))
    if args.guest_access_net:
        print(netgear.get_guest_access_network_info(args.test))
    if args.guest_access_net_5g:
        print(netgear.get_5g_guest_access_network_info(args.test))

    # does not work
    # print(netgear.get_current_app_bandwidth(args.test))
    # print(netgear.get_current_device_bandwidth(args.test))
    # print(netgear.get_current_app_bandwidth_by_mac(args.test))
    # print(netgear.get_available_channel(args.test))


if __name__ == '__main__':
    main()
