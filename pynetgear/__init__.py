#!/usr/bin/env python
# encoding: utf-8
"""Module to communicate with Netgear routers using the SOAP v2 API."""
from __future__ import print_function

from collections import namedtuple
import logging
from datetime import timedelta
import requests

import pynetgear.const as c
import pynetgear.helpers as h

_LOGGER = logging.getLogger(__name__)

Device = namedtuple(
    "Device", ["signal", "ip", "name", "mac", "type", "link_rate",
               "allow_or_block", "device_type", "device_model",
               "ssid", "conn_ap_mac"])


class Netgear():
    """Represents a session to a Netgear Router."""

    def __init__(self, password=None, host=None, user=None, port=None,  # noqa
                 ssl=False, url=None):
        """Initialize a Netgear session."""
        if not url and not host and not port:
            url = h.autodetect_url()

        if url:
            self.soap_url = url + "/soap/server_sa/"
        else:
            if not host:
                host = c.DEFAULT_HOST
            if not port:
                port = c.DEFAULT_PORT
            scheme = "https" if ssl else "http"
            self.soap_url = "{}://{}:{}/soap/server_sa/".format(scheme,
                                                                host, port)

        if not user:
            user = c.DEFAULT_USER

        self.username = user
        self.password = password
        self.port = port
        self.cookie = None
        self.config_started = False

    ##########################################################################
    # HELPERS
    ##########################################################################
    def login(self):
        """
        Login to the router.

        Will be called automatically by other actions.
        """
        v1_result = self.login_v1()
        if v1_result:
            return v1_result

        return self.login_v2()

    def _get_headers(self, service, method, need_auth=True):
        headers = h.get_soap_headers(service, method)
        # if the stored cookie is not a str then we are
        # probably using the old login method
        if need_auth and isinstance(self.cookie, str):
            headers["Cookie"] = self.cookie
        return headers

    def _make_request(self, service, method, params=None, body="",  # noqa
                      need_auth=True):
        """Make an API request to the router."""
        # If we have no cookie (v2) or never called login before (v1)
        # and we need auth, the request will fail for sure.
        if need_auth and not self.cookie:
            if not self.login():
                return False, None

        headers = self._get_headers(service, method, need_auth)

        if not body:
            if not params:
                params = ""
            if isinstance(params, dict):
                _map = params
                params = ""
                for k in _map:
                    params += "<" + k + ">" + _map[k] + "</" + k + ">\n"

            body = c.CALL_BODY.format(
                service=c.SERVICE_PREFIX + service,
                method=method, params=params
                )

        message = c.SOAP_REQUEST.format(session_id=c.SESSION_ID, body=body)

        try:
            response = requests.post(self.soap_url, headers=headers,
                                     data=message, timeout=30, verify=False)

            if need_auth and h.is_unauthorized_response(response):
                # let's discard the cookie because it probably expired (v2)
                # or the IP-bound (?) session expired (v1)
                self.cookie = None

                _LOGGER.warning(
                    "Unauthorized response, let's login and retry..."
                    )
                if self.login():
                    # reset headers with new cookie first
                    headers = self._get_headers(service, method, need_auth)
                    response = requests.post(
                        self.soap_url, headers=headers,
                        data=message, timeout=30, verify=False
                        )

            success = h.is_valid_response(response)

            if not success:
                _LOGGER.error("Invalid response")
                _LOGGER.debug(
                    "%s\n%s\n%s", response.status_code,
                    str(response.headers), response.text
                    )

            return success, response

        except requests.exceptions.RequestException:
            _LOGGER.exception("Error talking to API")
            # Maybe one day we will distinguish between
            # different errors..
            return False, None

    def _get(self, theLog, theService, theEndpoint,  # noqa
             parseNode, toParse, test=False):
        _LOGGER.info(theLog)
        success, response = self._make_request(
            theService,
            theEndpoint
            )

        if test:
            print(response.text)

        if not success:
            return None

        theInfo = h.to_get(parseNode, toParse, response)

        if not theInfo:
            return None

        return theInfo

    ##########################################################################
    # SERVICE_DEVICE_CONFIG
    ##########################################################################
    def login_v2(self):
        """Attempt login."""
        _LOGGER.debug("Login v2")
        self.cookie = None

        success, response = self._make_request(
            c.SERVICE_DEVICE_CONFIG, c.LOGIN,
            {"Username": self.username, "Password": self.password},
            None, False
            )

        if not success:
            return None

        if 'Set-Cookie' in response.headers:
            self.cookie = response.headers['Set-Cookie']
        else:
            _LOGGER.error("Login v2 ok but no cookie...")
            _LOGGER.debug(response.headers)

        return self.cookie

    # def logout(self):
    # def reboot(self):
    # def check_new_firmware(self):
    # def update_new_firmware(self):

    def config_start(self):
        """
        Start a configuration session.

        For managing router admin functionality (ie allowing/blocking devices)
        """
        _LOGGER.info("Config start")

        success, _ = self._make_request(
            c.SERVICE_DEVICE_CONFIG, c.CONFIGURATION_STARTED,
            {"NewSessionID": c.SESSION_ID}
            )

        self.config_started = success
        return success

    def config_finish(self):
        """
        End of a configuration session.

        Tells the router we're done managing admin functionality.
        """
        _LOGGER.info("Config finish")
        if not self.config_started:
            return True

        success, _ = self._make_request(
            c.SERVICE_DEVICE_CONFIG, c.CONFIGURATION_FINISHED,
            {"NewStatus": "ChangesApplied"}
            )

        self.config_started = not success
        return success

    # def get_block_device_enable_status(self):
    # def set_block_device_enable(self):
    # def enable_block_device_for_all(self):

    def set_block_device_by_mac(self, mac_addr,
                                device_status=c.BLOCK):
        """
        Allow or Block a device via its Mac Address.

        Pass in the mac address for the device that you want to set.
        Pass in the device_status you wish to set the device to: Allow
        (allow device to access the network) or Block (block the device
        from accessing the network).
        """
        _LOGGER.info("Allow block device")
        if self.config_started:
            _LOGGER.error(
                "Inconsistant configuration state, "
                "configuration already started"
                )
            return False

        if not self.config_start():
            _LOGGER.error("Could not start configuration")
            return False

        success, _ = self._make_request(
            c.SERVICE_DEVICE_CONFIG, c.SET_BLOCK_DEVICE_BY_MAC,
            {"NewAllowOrBlock": device_status, "NewMACAddress": mac_addr})

        if not success:
            _LOGGER.error("Could not successfully call allow/block device")
            return False

        if not self.config_finish():
            _LOGGER.error(
                "Inconsistant configuration state, "
                "configuration already finished"
                )
            return False

        return True

    def get_traffic_meter_enabled(self):
        """Parse GetTrafficMeterEnabled and return dict."""
        theLog = "Get DNS Masq Device ID"
        parseNode = f".//{c.GET_TRAFFIC_METER_ENABLED}Response"
        toParse = [
            'NewTrafficMeterEnable'
        ]

        theInfo = self._get(
            theLog, c.SERVICE_DEVICE_CONFIG,
            c.GET_TRAFFIC_METER_ENABLED, parseNode, toParse
            )

        return theInfo

    def get_traffic_meter_options(self):
        """Parse GetTrafficMeterOptions and return dict."""
        theLog = "Get Traffic Meter Options"
        parseNode = f".//{c.GET_TRAFFIC_METER_OPTIONS}Response"
        toParse = [
            'NewControlOption',
            'NewMonthlyLimit',
            'RestartHour',
            'RestartMinute',
            'RestartDay'
        ]

        theInfo = self._get(
            theLog, c.SERVICE_DEVICE_CONFIG,
            c.GET_TRAFFIC_METER_OPTIONS, parseNode, toParse
            )

        return theInfo

    def get_traffic_meter_statistics(self):
        """
        Return dict of traffic meter stats.

        Returns None if error occurred.
        """
        _LOGGER.info("Get traffic meter")

        def parse_text(text):
            """
            There are three kinds of values in the returned data.

            This function parses the different values and returns
            (total, avg), timedelta or a plain float
            """
            def tofloats(lst):
                return (float(t) for t in lst)
            try:
                if "/" in text:  # "6.19/0.88" total/avg
                    return tuple(tofloats(text.split('/')))

                if ":" in text:  # 11:14 hr:mn
                    hour, mins = tofloats(text.split(':'))
                    return timedelta(hours=hour, minutes=mins)

                return float(text)
            except ValueError:
                return None

        success, response = self._make_request(c.SERVICE_DEVICE_CONFIG,
                                               c.GET_TRAFFIC_METER_STATISTICS)
        if not success:
            return None

        success, node = h.find_node(
            response.text,
            f".//{c.GET_TRAFFIC_METER_STATISTICS}Response")
        if not success:
            return None

        return {t.tag: parse_text(t.text) for t in node}

    # def enable_traffic_meter(self):
    # def set_traffic_meter_options(self):

    ##########################################################################
    # SERVICE_PARENTAL_CONTROL
    ##########################################################################
    def login_v1(self):
        """Attempt login."""
        _LOGGER.debug("Login v1")

        body = c.LOGIN_V1_BODY.format(
            username=self.username, password=self.password
            )

        success, _ = self._make_request(
            c.SERVICE_PARENTAL_CONTROL, c.LOGIN_OLD, None, body, False
            )

        self.cookie = success

        return success

    # Does Not Work (Response Code 501)
    def get_parental_control_enable_status(self):
        """Parse GetEnableStatus and return dict."""
        theLog = "Get Parent Control Enable Status"
        parseNode = f".//{c.GET_PARENTAL_CONTROL_ENABLE_STATUS}Response"
        toParse = []

        theInfo = self._get(
            theLog, c.SERVICE_ADVANCED_QOS,
            c.GET_PARENTAL_CONTROL_ENABLE_STATUS, parseNode, toParse, True
            )

        return theInfo

    # def enable_parental_control(self):

    def get_all_mac_addresses(self):
        """Parse GetAllMACAddresses and return dict."""
        theLog = "Get All MAC Addresses"
        parseNode = f".//{c.GET_ALL_MAC_ADDRESSES}Response"
        toParse = [
            'AllMACAddresses'
        ]

        theInfo = self._get(
            theLog, c.SERVICE_PARENTAL_CONTROL, c.GET_ALL_MAC_ADDRESSES,
            parseNode, toParse,
            )

        return theInfo

    def get_dns_masq_device_id(self):
        """Parse GetDNSMasqDeviceID and return dict."""
        theLog = "Get DNS Masq Device ID"
        parseNode = f".//{c.GET_DNS_MASQ_DEVICE_ID}Response"
        toParse = [
            'NewDeviceID'
        ]

        theInfo = self._get(
            theLog, c.SERVICE_PARENTAL_CONTROL, c.GET_DNS_MASQ_DEVICE_ID,
            parseNode, toParse
            )

        return theInfo

    # def set_dns_masq_device_id(self):
    # def delete_mac_address(self):

    ##########################################################################
    # SERVICE_DEVICE_INFO
    ##########################################################################
    def getInfo(self):
        """Parse GetInfo and return dict."""
        theLog = "Get Info"
        parseNode = f".//{c.GET_INFO}Response"
        toParse = [
            'ModelName', 'Description', 'SerialNumber', 'Firmwareversion',
            'SmartAgentversion', 'FirewallVersion', 'VPNVersion',
            'OthersoftwareVersion', 'Hardwareversion', 'Otherhardwareversion',
            'FirstUseDate', 'DeviceName', 'FirmwareDLmethod',
            'FirmwareLastUpdate', 'FirmwareLastChecked', 'DeviceMode'
            ]

        theInfo = self._get(
            theLog, c.SERVICE_DEVICE_INFO, c.GET_INFO, parseNode, toParse
            )

        return theInfo

    def getSupportFeatureListXML(self):
        """Parse getSupportFeatureListXML and return dict."""
        theLog = "Get Support Feature List"
        parseNode = (
            f".//{c.GET_SUPPORT_FEATURE_LIST_XML}"
            "Response/newFeatureList/features"
        )

        toParse = [
            'DynamicQoS', 'OpenDNSParentalControl',
            'MaxMonthlyTrafficLimitation', 'AccessControl', 'SpeedTest',
            'GuestNetworkSchedule', 'TCAcceptance', 'SmartConnect',
            'AttachedDevice', 'NameNTGRDevice', 'PasswordReset'
            ]

        theInfo = self._get(
            theLog, c.SERVICE_DEVICE_INFO, c.GET_SUPPORT_FEATURE_LIST_XML,
            parseNode, toParse
            )

        return theInfo

    def get_attached_devices(self):  # noqa
        """
        Return list of connected devices to the router.

        Returns None if error occurred.
        """
        _LOGGER.info("Get attached devices")

        success, response = self._make_request(c.SERVICE_DEVICE_INFO,
                                               c.GET_ATTACHED_DEVICES)

        if not success:
            _LOGGER.error("Get attached devices failed")
            return None

        success, node = h.find_node(
            response.text,
            f".//{c.GET_ATTACHED_DEVICES}Response/NewAttachDevice")
        if not success:
            return None

        devices = []

        # Netgear inserts a double-encoded value for "unknown" devices
        decoded = node.text.strip().replace(
            c.UNKNOWN_DEVICE_ENCODED, c.UNKNOWN_DEVICE_DECODED
            )

        if not decoded or decoded == "0":
            _LOGGER.error("Can't parse attached devices string")
            _LOGGER.debug(node.text.strip())
            return devices

        entries = decoded.split("@")

        # First element is the total device count
        entry_count = None
        if len(entries) > 1:
            entry_count = h.convert(entries.pop(0), int)

        if entry_count is not None and entry_count != len(entries):
            _LOGGER.info(
                """Number of devices should \
                 be: %d but is: %d""", entry_count, len(entries))

        for entry in entries:
            info = entry.split(";")

            if not info:
                continue

            # Not all routers will report those
            signal = None
            link_type = None
            link_rate = None
            allow_or_block = None

            if len(info) >= 8:
                allow_or_block = info[7]
            if len(info) >= 7:
                link_type = info[4]
                link_rate = h.convert(info[5], int)
                signal = h.convert(info[6], int)

            if len(info) < 4:
                _LOGGER.warning("Unexpected entry: %s", info)
                continue

            ipv4, name, mac = info[1:4]

            devices.append(Device(signal, ipv4, name, mac,
                                  link_type, link_rate, allow_or_block,
                                  None, None, None, None))

        return devices

    def get_attached_devices_2(self):  # noqa
        """
        Return list of connected devices to the router with details.

        This call is slower and probably heavier on the router load.

        Returns None if error occurred.
        """
        _LOGGER.info("Get attached devices 2")

        success, response = self._make_request(c.SERVICE_DEVICE_INFO,
                                               c.GET_ATTACHED_DEVICES_2)
        if not success:
            return None

        success, devices_node = h.find_node(
            response.text,
            f".//{c.GET_ATTACHED_DEVICES_2}Response/NewAttachDevice")
        if not success:
            return None

        xml_devices = devices_node.findall("Device")
        devices = []
        for d in xml_devices:
            ip = h.xml_get(d, 'IP')
            name = h.xml_get(d, 'Name')
            mac = h.xml_get(d, 'MAC')
            signal = h.convert(h.xml_get(d, 'SignalStrength'), int)
            link_type = h.xml_get(d, 'ConnectionType')
            link_rate = h.xml_get(d, 'Linkspeed')
            allow_or_block = h.xml_get(d, 'AllowOrBlock')
            device_type = h.convert(h.xml_get(d, 'DeviceType'), int)
            device_model = h.xml_get(d, 'DeviceModel')
            ssid = h.xml_get(d, 'SSID')
            conn_ap_mac = h.xml_get(d, 'ConnAPMAC')
            devices.append(Device(signal, ip, name, mac, link_type, link_rate,
                                  allow_or_block, device_type, device_model,
                                  ssid, conn_ap_mac))

        return devices

    # def set_device_name_icon_by_mac(self):

    ##########################################################################
    # SERVICE_ADVANCED_QOS
    ##########################################################################
    def set_speed_test_start(self):
        """Start the speed test."""
        theLog = "Starting a speed test"

        _LOGGER.info(theLog)
        if self.config_started:
            _LOGGER.error(
                "Inconsistant configuration state, "
                "configuration already started"
                )
            return False

        if not self.config_start():
            _LOGGER.error("Could not start configuration")
            return False

        success, _ = self._make_request(
            c.SERVICE_ADVANCED_QOS,
            c.SET_SPEED_TEST_START
            )

        if not success:
            _LOGGER.error("Could not successfully start speed test")
            return False

        if not self.config_finish():
            _LOGGER.error(
                "Inconsistant configuration state, "
                "configuration already finished"
                )
            return False

        return True

    def get_speed_test_result(self):
        """Get the speed test result and return dict."""
        theLog = "Get Speed Test Result"
        parseNode = f".//{c.GET_SPEED_TEST_RESULT}Response"
        toParse = [
            'NewOOKLAUplinkBandwidth',
            'NewOOKLADownlinkBandwidth',
            'AveragePing'
            ]

        theInfo = self._get(
            theLog, c.SERVICE_ADVANCED_QOS, c.GET_SPEED_TEST_RESULT,
            parseNode, toParse
            )

        return theInfo

    def getQoSEnableStatus(self):
        """Parse getQoSEnableStatus and return dict."""
        theLog = "Get QOS Enable Status"
        parseNode = f".//{c.GET_QOS_ENABLE_STATUS}Response"
        toParse = [
            'NewQoSEnableStatus'
            ]

        theInfo = self._get(
            theLog, c.SERVICE_ADVANCED_QOS, c.GET_QOS_ENABLE_STATUS,
            parseNode, toParse
            )

        return theInfo

    # def set_qos_enable_status(self):

    def get_bandwidth_control_options(self):
        """Parse GetBandwidthControlOptions and return dict."""
        theLog = "Get Bandwidth Control Options"
        parseNode = f".//{c.GET_BANDWIDTH_CONTROL_OPTIONS}Response"
        toParse = [
            'NewUplinkBandwidth', 'NewDownlinkBandwidth', 'NewSettingMethod'
            ]

        theInfo = self._get(
            theLog, c.SERVICE_ADVANCED_QOS, c.GET_BANDWIDTH_CONTROL_OPTIONS,
            parseNode, toParse
            )

        return theInfo

    # def set_bandwidth_control_options(self):

    # Does Not Work
    def get_current_app_bandwidth(self):
        """Parse GetCurrentAppBandwidth and return dict."""
        theLog = "Get Current App Bandwidth"
        parseNode = f".//{c.GET_CURRENT_APP_BANDWIDTH}Response"
        toParse = []

        theInfo = self._get(
            theLog, c.SERVICE_ADVANCED_QOS, c.GET_CURRENT_APP_BANDWIDTH,
            parseNode, toParse
            )

        return theInfo

    # Does Not Work
    def get_current_device_bandwidth(self):
        """Parse GetCurrentDeviceBandwidth and return dict."""
        theLog = "Get Current Device Bandwidth"
        parseNode = f".//{c.GET_CURRENT_DEVICE_BANDWIDTH}Response"
        toParse = []

        theInfo = self._get(
            theLog, c.SERVICE_ADVANCED_QOS, c.GET_CURRENT_DEVICE_BANDWIDTH,
            parseNode, toParse
            )

        return theInfo

    # Does Not Work
    def get_current_app_bandwidth_by_mac(self):
        """Parse GetCurrentAppBandwidthByMAC and return dict."""
        theLog = "Get Current Device Bandwidth by MAC"
        parseNode = f".//{c.GET_CURRENT_APP_BANDWIDTH_BY_MAC}Response"
        toParse = []

        theInfo = self._get(
            theLog, c.SERVICE_ADVANCED_QOS, c.GET_CURRENT_APP_BANDWIDTH_BY_MAC,
            parseNode, toParse
            )

        return theInfo

    ##########################################################################
    # SERVICE_WLAN_CONFIGURATION
    ##########################################################################
    def get_guest_access_enabled(self):
        """Parse GetGuestAccessEnabled and return dict."""
        theLog = "Get Guest Access Enabled"
        parseNode = f".//{c.GET_GUEST_ACCESS_ENABLED}Response"
        toParse = ['NewGuestAccessEnabled']

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION, c.GET_GUEST_ACCESS_ENABLED,
            parseNode, toParse
            )

        return theInfo

    # Need to handle different endpoints
    def get_5g1_guest_access_enabled(self):
        """Parse Get5GGuestAccessEnabled and return dict."""
        theLog = "Get 5G Guest Access Enabled"
        parseNode = f".//{c.GET_5G1_GUEST_ACCESS_ENABLED}Response"
        toParse = ['NewGuestAccessEnabled']

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION,
            c.GET_5G1_GUEST_ACCESS_ENABLED, parseNode, toParse
            )

        return theInfo

    # Need to handle different endpoints
    def get_5g1_guest_access_enabled_2(self):
        """Parse Get5G1GuestAccessEnabled and return dict."""
        theLog = "Get 5G1 Guest Access Enabled 2"
        parseNode = f".//{c.GET_5G1_GUEST_ACCESS_ENABLED_2}Response"
        toParse = ['NewGuestAccessEnabled']

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION,
            c.GET_5G1_GUEST_ACCESS_ENABLED_2, parseNode, toParse
            )

        return theInfo

    # Need to handle different endpoints
    # My router does not support
    def get_5g_guest_access_enabled_2(self):
        """Parse Get5GGuestAccessEnabled2 and return dict."""
        theLog = "Get 5G Guest Access Enabled 2"
        parseNode = f".//{c.GET_5G_GUEST_ACCESS_ENABLED_2}Response"
        toParse = ['NewGuestAccessEnabled']

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION,
            c.GET_5G_GUEST_ACCESS_ENABLED_2, parseNode, toParse
            )

        return theInfo

    # def set_guest_access_enabled(self):
    # def set_guest_access_enabled_2(self):
    # def set_5g1_guest_access_enabled(self):
    # def set_5g1_guest_access_enabled_2(self):
    # def set_5g_guest_access_enabled_2(self):

    def get_wpa_security_keys(self):
        """Parse GetWPASecurityKeys and return dict."""
        theLog = "Get WPA Security Keys"
        parseNode = f".//{c.GET_WPA_SECURITY_KEYS}Response"
        toParse = ['NewWPAPassphrase']

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION, c.GET_WPA_SECURITY_KEYS,
            parseNode, toParse
            )

        return theInfo

    def get_5g_wpa_security_keys(self):
        """Parse Get5GWPASecurityKeys and return dict."""
        theLog = "Get 5G WPA Security Keys"
        parseNode = f".//{c.GET_5G_WPA_SECURITY_KEYS}Response"
        toParse = ['NewWPAPassphrase']

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION, c.GET_5G_WPA_SECURITY_KEYS,
            parseNode, toParse
            )

        return theInfo

    def get_5g_info(self):
        """Parse Get5GInfo and return dict."""
        theLog = "Get 5G Info"
        parseNode = f".//{c.GET_5G_INFO}Response"
        toParse = [
            'NewEnable',
            'NewSSIDBroadcast',
            'NewStatus',
            'NewSSID',
            'NewRegion',
            'NewChannel',
            'NewWirelessMode',
            'NewBasicEncryptionModes',
            'NewWEPAuthType',
            'NewWPAEncryptionModes',
            'NewWLANMACAddress',
        ]

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION, c.GET_5G_INFO,
            parseNode, toParse
            )

        return theInfo

    def get_2g_info(self):
        """Parse GetInfo and return dict."""
        theLog = "Get 2G Info"
        parseNode = f".//{c.GET_2G_INFO}Response"
        toParse = [
            'NewEnable',
            'NewSSIDBroadcast',
            'NewStatus',
            'NewSSID',
            'NewRegion',
            'NewChannel',
            'NewWirelessMode',
            'NewBasicEncryptionModes',
            'NewWEPAuthType',
            'NewWPAEncryptionModes',
            'NewWLANMACAddress',
        ]

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION, c.GET_2G_INFO,
            parseNode, toParse
            )

        return theInfo

    # def set_5g_wlan_wpa_psk_by_passphrase(self):

    # Response is GetInfo
    def get_available_channel(self):
        """Parse GetAvailableChannel and return dict."""
        theLog = "Get Available Channel"
        parseNode = f".//{c.GET_AVAILABLE_CHANNEL}Response"
        toParse = []

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION, c.GET_AVAILABLE_CHANNEL,
            parseNode, toParse
            )

        return theInfo

    def get_guest_access_network_info(self):
        """Parse GetGuestAccessNetworkInfo and return dict."""
        theLog = "Get Guest Access Network Info"
        parseNode = f".//{c.GET_GUEST_ACCESS_NETWORK_INFO}Response"
        toParse = [
            'NewSSID',
            'NewSecurityMode',
            'NewKey',
            'UserSetSchedule',
            'Schedule',
        ]

        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION,
            c.GET_GUEST_ACCESS_NETWORK_INFO, parseNode, toParse
            )

        return theInfo

    # def set_guest_access_network(self):

    def get_5g_guest_access_network_info(self):
        """Parse Get5GGuestAccessNetworkInfo and return dict."""
        theLog = "Get 5G Guest Access Network Info"
        parseNode = f".//{c.GET_5G_GUEST_ACCESS_NETWORK_INFO}Response"
        toParse = [
            'NewSSID',
            'NewSecurityMode',
            'NewKey',
            'UserSetSchedule',
            'Schedule',
        ]
        theInfo = self._get(
            theLog, c.SERVICE_WLAN_CONFIGURATION,
            c.GET_5G_GUEST_ACCESS_NETWORK_INFO, parseNode, toParse
            )

        return theInfo
