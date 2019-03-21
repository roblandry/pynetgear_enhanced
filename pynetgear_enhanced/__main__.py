"""Run PyNetgear from the command-line."""
from . import Netgear
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
    parser.add_argument(
        '--info', help='getInfo',
        required=False, action='store_true')
    parser.add_argument(
        '--check_fw', help='check_new_firmware',
        required=False, action='store_true')
    parser.add_argument(
        '--attached_devices', help='get_attached_devices',
        required=False, action='store_true')
    parser.add_argument(
        '--attached_devices2', help='get_attached_devices_2',
        required=False, action='store_true')
    parser.add_argument(
        '--support_feature', help='getSupportFeatureListXML',
        required=False, action='store_true')
    parser.add_argument(
        '--bw_control', help='get_bandwidth_control_options',
        required=False, action='store_true')
    parser.add_argument(
        '--qos_enabled', help='getQoSEnableStatus',
        required=False, action='store_true')
    parser.add_argument(
        '--mac_address', help='get_all_mac_addresses',
        required=False, action='store_true')
    parser.add_argument(
        '--dns_masq', help='get_dns_masq_device_id',
        required=False, action='store_true')
    parser.add_argument(
        '--traffic_meter', help='get_traffic_meter_statistics',
        required=False, action='store_true')
    parser.add_argument(
        '--traffic_meter_enabled', help='get_traffic_meter_enabled',
        required=False, action='store_true')
    parser.add_argument(
        '--traffic_meter_options', help='get_traffic_meter_options',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access', help='get_guest_access_enabled',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access_5g', help='get_5g1_guest_access_enabled',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access_5g1', help='get_5g1_guest_access_enabled_2',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access_5g2', help='get_5g_guest_access_enabled_2',
        required=False, action='store_true')
    parser.add_argument(
        '--wpa_key', help='get_wpa_security_keys',
        required=False, action='store_true')
    parser.add_argument(
        '--wpa_key_5g', help='get_5g_wpa_security_keys',
        required=False, action='store_true')
    parser.add_argument(
        '--get_5g_info', help='get_5g_info',
        required=False, action='store_true')
    parser.add_argument(
        '--get_2g_info', help='get_2g_info',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access_net', help='get_guest_access_network_info',
        required=False, action='store_true')
    parser.add_argument(
        '--guest_access_net_5g', help='get_5g_guest_access_network_info',
        required=False, action='store_true')
    parser.add_argument(
        '--speed_test_start', help='set_speed_test_start',
        required=False, action='store_true')
    parser.add_argument(
        '--speed_test_result', help='get_speed_test_result',
        required=False, action='store_true')

    parser.add_argument(
        '--guest_access_enable',
        help='Enable Guest 2.4G Wifi: '
        'True|true|T|t|Yes|yes|Y|y|1, '
        'False|false|F|f|No|no|N|n|0',
        required=False)
    parser.add_argument(
        '--guest_access_enable2',
        help='Enable Guest 2.4G Wifi: '
        'True|true|T|t|Yes|yes|Y|y|1, '
        'False|false|F|f|No|no|N|n|0',
        required=False)
    parser.add_argument(
        '--guest_access_enable_5g',
        help='Enable Guest 5G Wifi: '
        'True|true|T|t|Yes|yes|Y|y|1, '
        'False|false|F|f|No|no|N|n|0',
        required=False)
    parser.add_argument(
        '--guest_access_enable_5g1',
        help='Enable Guest 5G Wifi: '
        'True|true|T|t|Yes|yes|Y|y|1, '
        'False|false|F|f|No|no|N|n|0',
        required=False)
    parser.add_argument(
        '--guest_access_enable_5g2',
        help='Enable Guest 5G Wifi: '
        'True|true|T|t|Yes|yes|Y|y|1, '
        'False|false|F|f|No|no|N|n|0',
        required=False)

    args = parser.parse_args()

    if args.password:
        netgear = Netgear(args.password)
    if args.info:
        print(netgear.getInfo(args.test))
    if args.check_fw:
        print(netgear.check_new_firmware(args.test))
    if args.attached_devices:
        print(netgear.get_attached_devices(args.test))
    if args.attached_devices2:
        print(netgear.get_attached_devices_2(args.test))
    if args.traffic_meter:
        print(netgear.get_traffic_meter_statistics(args.test))
    if args.support_feature:
        print(netgear.getSupportFeatureListXML(args.test))
    if args.bw_control:
        print(netgear.get_bandwidth_control_options(args.test))
    if args.qos_enabled:
        print(netgear.getQoSEnableStatus(args.test))
    if args.mac_address:
        print(netgear.get_all_mac_addresses(args.test))
    if args.dns_masq:
        print(netgear.get_dns_masq_device_id(args.test))
    if args.traffic_meter_enabled:
        print(netgear.get_traffic_meter_enabled(args.test))
    if args.traffic_meter_options:
        print(netgear.get_traffic_meter_options(args.test))
    if args.guest_access:
        print(netgear.get_guest_access_enabled(args.test))
    if args.guest_access_5g:
        print(netgear.get_5g1_guest_access_enabled(args.test))
    if args.guest_access_5g1:
        print(netgear.get_5g1_guest_access_enabled_2(args.test))
    if args.guest_access_5g2:
        print(netgear.get_5g_guest_access_enabled_2(args.test))
    if args.wpa_key:
        print(netgear.get_wpa_security_keys(args.test))
    if args.wpa_key_5g:
        print(netgear.get_5g_wpa_security_keys(args.test))
    if args.get_5g_info:
        print(netgear.get_5g_info(args.test))
    if args.get_2g_info:
        print(netgear.get_2g_info(args.test))
    if args.guest_access_net:
        print(netgear.get_guest_access_network_info(args.test))
    if args.guest_access_net_5g:
        print(netgear.get_5g_guest_access_network_info(args.test))
    if args.speed_test_start:
        print(netgear.set_speed_test_start(args.test))
        time.sleep(30)
        print(netgear.get_speed_test_result(args.test))
    if args.speed_test_result:
        print(netgear.get_speed_test_result(args.test))

    if args.guest_access_enable:
        print(netgear.set_guest_access_enabled(
            args.guest_access_enable, args.test))
    if args.guest_access_enable2:
        print(netgear.set_guest_access_enabled_2(
            args.guest_access_enable_2, args.test))
    if args.guest_access_enable_5g:
        print(netgear.set_5g_guest_access_enabled(
            args.guest_access_enable_5g, args.test))
    if args.guest_access_enable_5g1:
        print(netgear.set_5g_guest_access_enabled_2(
            args.guest_access_enable_5g1, args.test))
    if args.guest_access_enable_5g2:
        print(netgear.set_5g1_guest_access_enabled_2(
            args.guest_access_enable_5g2, args.test))

    # does not work
    # print(netgear.get_current_app_bandwidth(args.test))
    # print(netgear.get_current_device_bandwidth(args.test))
    # print(netgear.get_current_app_bandwidth_by_mac(args.test))
    # print(netgear.get_parental_control_enable_status(args.test))
    # print(netgear.get_available_channel(args.test))


if __name__ == '__main__':
    main()
