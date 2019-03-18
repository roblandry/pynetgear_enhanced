"""Run PyNetgear from the command-line."""
from pynetgear import Netgear
import sys
import argparse
import time


def main():
    """Scan for devices and print results."""

    parser = argparse.ArgumentParser(description='ADD YOUR DESCRIPTION HERE')
    parser.add_argument('-p', '--password', help='Your Password', required=True)
    parser.add_argument('--info', help='getInfo', required=False, action='store_true')
    parser.add_argument('--attached_devices', help='get_attached_devices', required=False, action='store_true')
    parser.add_argument('--attached_devices2', help='get_attached_devices_2', required=False, action='store_true')
    parser.add_argument('--traffic_meter', help='get_traffic_meter', required=False, action='store_true')
    parser.add_argument('--support_feature', help='getSupportFeatureListXML', required=False, action='store_true')
    parser.add_argument('--bw_control', help='get_bandwidth_control_options', required=False, action='store_true')
    parser.add_argument('--qos_enabled', help='getQoSEnableStatus', required=False, action='store_true')
    parser.add_argument('--mac_address', help='get_all_mac_addresses', required=False, action='store_true')
    parser.add_argument('--dns_masq', help='get_dns_masq_device_id', required=False, action='store_true')
    parser.add_argument('--traffic_meter_enabled', help='get_traffic_meter_enabled', required=False, action='store_true')
    parser.add_argument('--traffic_meter_options', help='get_traffic_meter_options', required=False, action='store_true')
    parser.add_argument('--guest_access', help='get_guest_access_enabled', required=False, action='store_true')
    parser.add_argument('--guest_access_5g', help='get_5g1_guest_access_enabled', required=False, action='store_true')
    parser.add_argument('--guest_access_5g1', help='get_5g1_guest_access_enabled_2', required=False, action='store_true')
    parser.add_argument('--guest_access_5g2', help='get_5g_guest_access_enabled_2', required=False, action='store_true')
    parser.add_argument('--wpa_key', help='get_wpa_security_keys', required=False, action='store_true')
    parser.add_argument('--wpa_key_5g', help='get_5g_wpa_security_keys', required=False, action='store_true')
    parser.add_argument('--get_5g_info', help='get_5g_info', required=False, action='store_true')
    parser.add_argument('--get_2g_info', help='get_2g_info', required=False, action='store_true')
    parser.add_argument('--guest_access_net', help='get_guest_access_network_info', required=False, action='store_true')
    parser.add_argument('--guest_access_net_5g', help='get_5g_guest_access_network_info', required=False, action='store_true')
    parser.add_argument('--speed_test_start', help='set_speed_test_start', required=False, action='store_true')
    parser.add_argument('--speed_test_result', help='get_speed_test_result', required=False, action='store_true')

    args = parser.parse_args()

    if args.password:
        netgear = Netgear(args.password)
    if args.info:
        print(netgear.getInfo())
    if args.attached_devices:
        print(netgear.get_attached_devices())
    if args.attached_devices2:
        print(netgear.get_attached_devices_2())
    if args.traffic_meter:
        print(netgear.get_traffic_meter())
    if args.support_feature:
        print(netgear.getSupportFeatureListXML())
    if args.bw_control:
        print(netgear.get_bandwidth_control_options())
    if args.qos_enabled:
        print(netgear.getQoSEnableStatus())
    if args.mac_address:
        print(netgear.get_all_mac_addresses())
    if args.dns_masq:
        print(netgear.get_dns_masq_device_id())
    if args.traffic_meter_enabled:
        print(netgear.get_traffic_meter_enabled())
    if args.traffic_meter_options:
        print(netgear.get_traffic_meter_options())
    if args.guest_access:
        print(netgear.get_guest_access_enabled())
    if args.guest_access_5g:
        print(netgear.get_5g1_guest_access_enabled())
    if args.guest_access_5g1:
        print(netgear.get_5g1_guest_access_enabled_2())
    if args.guest_access_5g2:
        print(netgear.get_5g_guest_access_enabled_2())
    if args.wpa_key:
        print(netgear.get_wpa_security_keys())
    if args.wpa_key_5g:
        print(netgear.get_5g_wpa_security_keys())
    if args.get_5g_info:
        print(netgear.get_5g_info())
    if args.get_2g_info:
        print(netgear.get_2g_info())
    if args.guest_access_net:
        print(netgear.get_guest_access_network_info())
    if args.guest_access_net_5g:
        print(netgear.get_5g_guest_access_network_info())
    if args.speed_test_start:
        print(netgear.set_speed_test_start())
        time.sleep(30)
        print(netgear.get_speed_test_result())
    if args.speed_test_result:
        print(netgear.get_speed_test_result())
    # does not work
    # print(netgear.get_current_app_bandwidth())
    # print(netgear.get_current_device_bandwidth())
    # print(netgear.get_current_app_bandwidth_by_mac())
    # print(netgear.get_parental_control_enable_status())
    # print(netgear.get_available_channel())


    #print(netgear.get_traffic_meter_statistics())

    #devices = netgear.get_attached_devices()

    #if devices is None:
    #    print("Error communicating with the Netgear router")

    #else:
    #    for i in devices:
    #        print(i)


if __name__ == '__main__':
    main()
