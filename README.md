# pyNetgear_Enhanced #

pyNetgear_Enhanced provides an easy to use Python API to control your Netgear router. It uses the SOAP-api on modern Netgear routers to communicate. It is built by reverse engineering the requests made by the [NETGEAR Genie app](https://play.google.com/store/apps/details?id=com.dragonflow).

pyNetgear_Enhanced works with Python 3.

If you are connected to the network of the Netgear router, a host is optional.
If you are connected via a wired connection to the Netgear router, a password is optional.
The username defaults to admin.
The port defaults to 5000.
The ssl defaults to false.
You can specify url and it will take precedence on host/port/ssl parameters.
This allows the use of HTTPS, `https://orbilogin.com` for example.

Thanks to:  
[MatMaul](https://github.com/MatMaul/pynetgear) for the original code.  
[gruijter](https://github.com/gruijter/netgear.js) for additional SOAP endpoints.  


## It currently supports the following operations: ##

* **login**  
Logs in to the router. Will return True or False to indicate success.

* **allow_block_device**  
Allows user to block/unblock devices from accessing router by specifying mac_addr and new device_status (Block/Allow)  
**Note:** In order to use this function, Remote Management _must_ be enabled in the router's admin settings.

#### SERVICE_DEVICE_CONFIG: ####

* **check_new_firmware**  
Return a dict containing the Firmware info.

* **set_block_device_enable**  
Enable/Disable Access Control.

* **get_block_device_enable_status**  
Return a dict containing the Status of Access Control.

* **get_traffic_meter_statistics**  
Return a dict containing the traffic meter information from the router (if enabled in the webinterface).

* **enable_traffic_meter**  
Enable/Disable Traffic Meter.

* **get_traffic_meter_enabled**  
Return a dict containing the Status of Traffic Meter.

* **get_traffic_meter_options**  
Return a dict containing the Traffic Meter Options.

#### SERVICE_PARENTAL_CONTROL: ####

* **enable_parental_control**  
Enable/Disable Parental Control.

* **get_parental_control_enable_status**  
Return a dict containing the Status of Parental Control.

* **get_all_mac_addresses**  
Return a dict containing the MAC Addresses.

* **get_dns_masq_device_id**  
Return a dict containing the DNS Masq device IDs.

#### SERVICE_DEVICE_INFO: ####

* **get_info**  
Return a dict containing the Router Information.

* **get_support_feature_list_XML**  
Return a dict containing the Supported Features.

* **get_attached_devices**  
Returns a list of named tuples describing the device signal, ip, name, mac, type, link_rate and allow_or_block.

* **get_attached_devices_2**  
Returns a list of named tuples describing the device signal, ip, name, mac, type, link_rate, allow_or_block, device_type, device_model, ssid and conn_ap_mac.  
This call is slower and probably heavier on the router load.

#### SERVICE_ADVANCED_QOS: ####

* **set_speed_test_start**  
Starts the Speed Test.

* **get_speed_test_result**  
Return a dict containing the Speed Test Results.  
You will have to wait several seconds following starting the speed test to get the final results.

* **set_qos_enable_status**  
Enable/Disable QOS.

* **get_qos_enable_status**  
Return a dict containing the Status of QOS.

* **get_bandwidth_control_options**  
Return a dict containing the Bandwidth Control Options.

#### SERVICE_WLAN_CONFIGURATION: ####

* **set_guest_access_enabled**  
Enable/Disable 2.4g Guest WiFi.

* **get_guest_access_enabled**  
Return a dict containing the Status of 2.4g Guest Wifi.

* **set_guest_access_enabled_2**  
Enable/Disable 2.4g Guest WiFi 2.

* **set_5g_guest_access_enabled**  
Enable/Disable 5g Guest Wifi.

* **get_5g_guest_access_enabled**  
Return a dict containing the Status of 5g Guest Wifi.

* **get_wpa_security_keys**  
Return a dict containing the 2.4g WPA Key.

* **get_5g_wpa_security_keys**  
Return a dict containing the 5g WPA Key.

* **get_2g_info**  
Return a dict containing the 2.4g Info.

* **get_5g_info**  
Return a dict containing the 5g Info.

* **get_guest_access_network_info**  
Return a dict containing the 2.4g Guest Network Info.

* **get_5g_guest_access_network_info**  
Return a dict containing the 5g Guest Network Info.


## Installation ##

You can install pyNetgear_Enhanced from PyPi using:  
`pip3 install pynetgear_enhanced`.


## Usage ##

For a list of commands run from the console:  
`$ python3 -m pynetgear_enhanced -h`

For testing append a -t to the command from the console.  
`$ python3 -m pynetgear_enhanced -p='MyEscapedPassword!' --check_fw -t`

To use within your Python scripts:
```python
from pynetgear import Netgear

netgear = Netgear(password=mypassword)

for i in netgear.get_attached_devices():
    print i
```


## Supported routers ##
It has been tested with the Netgear RAX80 router. Previous testing was done with the R6300 and WNDR4500 routers prior to the addition of the advanced options. According to the NETGEAR Genie app description, the following routers should also work:

 * Netgear RAX80
 * Netgear Orbi
 * Netgear R7800
 * Netgear R7500v2
 * Netgear R7000
 * Netgear R6900
 * Netgear R6300
 * Netgear R6250
 * Netgear R6200
 * Netgear R6100
 * Netgear N300 - Model: C3000 (Port 80)
 * Netgear Centria (WNDR4700, WND4720)
 * Netgear WNDR4500
 * Netgear WNDR4300
 * Netgear WNDR4000
 * Netgear WNDR3800
 * Netgear WNDR3700v3
 * Netgear WNDR3700v2
 * Netgear WNDR3400v2
 * Netgear WNR3500Lv2
 * Netgear WNR2200
 * Netgear WNR2000v3
 * Netgear WNR2000v4 (Port 80)
 * Netgear WNR1500
 * Netgear WNR1000v2
 * Netgear WNR1000v3
 * Netgear WNDRMAC
 * Netgear WNR612v2
