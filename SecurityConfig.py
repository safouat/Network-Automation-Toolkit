from napalm import get_network_driver
from napalm.base.exceptions import LockError, UnlockError
import getpass
from switches import switches
# ----------ACL AUTOMATION------------------ #
# ----PORT SECURITY IMPLEMENTATION---------- #
# ----DHCP SNOOPING IMPLEMENTATION-------- #
# -----DYNAMIC ARP INSPECTION------------ #

def get_napalm_connection(ip_address,username,password):
    driver = get_network_driver('ios')
    device = driver(hostname=ip_address, username=username, password=password)
    
    try:
        device.open()
    except Exception as e:
        print(f"Error connecting to {ip_address}: {e}")
        return None
    
    return device

def configure_STANDARDacl(ip,permitADD, DenyADD, wildmask, interfaceACL,username,password):
    choice1 = input('Do you want to use numbered ACL? (YES or NO): ').lower()
    device = get_napalm_connection(ip,username,password)
    if choice1 == 'yes':
        n = int(input('Enter the number of ACL: '))  # n should be in 100-199 or 2000-2699
        config_commands = [
            f"access-list {n} permit {permitADD}",
            f"access-list {n} deny {DenyADD} {wildmask}",
            f"access-list {n} permit any",
        ]
    else:
        n = input('Enter the name of ACL: ')
        config_commands = [
            f"ip access-list standard {n}",
            f"permit {permitADD}",
            f"deny {DenyADD} {wildmask}",
            "permit any",
        ]
   
    choice2 = input('Do you want INBOUND? (YES or NO): ').lower()
    a = 'in' if choice2 == 'yes' else 'out'
    
    config_commands += [
        f"int {interfaceACL}",
        f"ip access-group {n} {a}",
    ]
    
    try:
        device.load_merge_candidate(config="\n".join(config_commands))
        diffs = device.compare_config()
        if diffs:
      print("Proposed configuration changes:")
            print(diffs)
            device.commit_config()
            print("Configuration committed.")
        else:
            print("No configuration changes to commit.")
    except LockError:
        print("Configuration lock error.")
    except UnlockError:
        print("Configuration unlock error.")
    except Exception as e:
        print(f"Error configuring ACL: {e}")
    finally:
        device.discard_config()

def construct_STANDARDACL_LIST():
    ACL_LIST = {}

    ask = 'y'
    while ask == 'y':
        otherACL = 'y'
        while otherACL == 'y':
            ip = input('\nEnter the IP address of the device: ')
            name = input('Enter the hostname: ')

            deny = input('\nEnter the IP address of network deny: ')
            neighbors = input('Enter the IP addresses permitting separated by commas (e.g., 192.168.23.0,192.168.13.0): ')
            neighbor_list = [neighbor.strip() for neighbor in neighbors.split(',')]
            wildMask = input('Enter the WildMask of the network: ')
            INT = input('Enter the interface of the network that should be configured ACL: ')

            ACL_LIST[name] = {'ip': ip, 'neighbors': neighbor_list, 'wildMask': wildMask, 'DENY': deny, 'INTERFACE': INT}
            otherACL = input("\nDo you want to add another ACL? Answer with 'y' or 'n': ").lower()
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return ACL_LIST

#---------------ACL CRUD---------------#
def CrudACL(ip,username,password):
    choice = input('Do you want to delete or insert? ').lower()
    config_commands = []
    device = get_napalm_connection(ip, username, password)
    
    if choice == 'delete':
        entry_number = input('Enter the entry number: ')
        config_commands.append(f"no {entry_number}")
    else:
        entry_number = input('Enter the entry number: ')
        PVD = input('Enter permit or deny: ')
        ip = input('Enter IP address: ')
        wildmask = input('Enter the wildmask: ')
  config_commands.append(f"{entry_number} {PVD} {ip} {wildmask}")
    
    try:
        device.load_merge_candidate(config="\n".join(config_commands))
        diffs = device.compare_config()
        if diffs:
            print("Proposed configuration changes:")
            print(diffs)
            device.commit_config()
            print("Configuration committed.")
        else:
            print("No configuration changes to commit.")
    except LockError:
        print("Configuration lock error.")
    except UnlockError:
        print("Configuration unlock error.")
    except Exception as e:
        print(f"Error configuring ACL: {e}")
    finally:
        device.discard_config()

#--------------------EXTENDED ACL----------------#
def construct_ExtendedACL_LIST():
    ACL_LIST= {}

    ask = 'y'
    while ask == 'y':
        otherACL = 'y'
        while otherACL == 'y':
            ip = input('\nEnter the IP address of the device: ')
            name = input('Enter the hostname: ')

            SOURCEP = input('\nEnter the IP address of SOURCE permiting : ')
            SOURCEP_list = [neighbor.strip() for neighbor in SOURCEP.split(',')]
            wildMask1= input('Enter the WildMask of the network : ')
            DESTINATIONP_list = [neighbor.strip() for neighbor in wildMask1.split(',')]
            DESTINATIONP= input('Enter the IP addresses OF DESTINATION permiting : ')
            DESTINATIONP_list = [neighbor.strip() for neighbor in DESTINATIONP.split(',')]
            wildMask2 = input('Enter the WildMask of the network: ')
            DESTINATIONP_list = [neighbor.strip() for neighbor in wildMask2.split(',')]


            SOURCED = input('\nEnter the IP address of SOURCE Deny : ')
            SOURCED_list = [SOURCED.strip() for neighbor in SOURCED.split(',')]
            wildMask3= input('Enter the WildMask of the network deny: ')
            wildMask3_list = [neighbor.strip() for neighbor in wildMask3.split(',')]
            DESTINATIOND= input('Enter the IP addresses OF DESTINATION Deny : ')
            DESTINATIOND_list = [DESTINATIOND.strip() for neighbor in DESTINATIOND.split(',')]
            wildMask4 = input('Enter the WildMask of the network permit: ')
            wildMask4_list = [neighbor.strip() for neighbor in wildMask4.split(',')]
         protocol= input('Enter the portocol:UDP,TCP,ICMP,EIGRP,OSPF ')
            INT=input('Enter the interface on wich the ACL WILL BE CONFIGURED ')


            ACL_LIST[name] = {'ip': ip,'protocol':protocol, 'SOURCEP': SOURCEP_list, 'wildMask1': wildMask1, 'DESTINATIONP': DESTINATIONP_list,'wildMask2': wildMask2,'SOURCED': SOURCED_list, 'wildMask3':>
            otherACL = input("\nDo you want to add another ACL? Answer with 'y' or 'n': ").lower()
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return  ACL_LIST




def configure_extended_acl(ip,source_permit, source_wildmask, dest_permit, dest_wildmask, source_deny, source_deny_wildmask, dest_deny, dest_deny_wildmask, protocol, interface,username,password):
    choice1 = input('Do you want to use numbered ACL? (YES or NO): ').lower()
    device = get_napalm_connection(ip,username,password)
    if choice1 == 'yes':
        n = int(input('Enter the number of ACL: '))  # n should be in 100-199 or 2000-2699
        if protocol == 'tcp' or protocol == 'udp':  # Corrected the comparison operator
            n1 = int(input('Enter the number of port: '))
            config_commands = [
            f"access-list {n} permit {protocol} {source_permit} {source_wildmask} {dest_permit} {dest_wildmask} eq {n1}",
            f"access-list {n} deny {protocol} {source_deny} {source_deny_wildmask} {dest_deny} {dest_deny_wildmask} eq {n1}",
        ]
        else:
            config_commands = [
            f"access-list {n} permit {protocol} {source_permit} {source_wildmask} {dest_permit} {dest_wildmask}",
            f"access-list {n} deny {protocol} {source_deny} {source_deny_wildmask} {dest_deny} {dest_deny_wildmask}",
        ]

    else:
        n = input('Enter the name of ACL: ')
        if protocol == 'tcp' or protocol == 'udp':  # Corrected the comparison operator
            n1 = int(input('Enter the number of port: '))
            config_commands = [
        f'ip access-list extended {n}',
        f'permit {protocol} {source_permit} {source_wildmask} {dest_permit} {dest_wildmask} eq {n1}',
        f'deny {protocol} {source_deny} {source_deny_wildmask} {dest_deny} {dest_deny_wildmask} eq {n1}',
        ]
        else:
            config_commands = [
        f'ip access-list extended {n}',
        f'permit {protocol} {source_permit} {source_wildmask} {dest_permit} {dest_wildmask}',
        f'deny {protocol} {source_deny} {source_deny_wildmask} {dest_deny} {dest_deny_wildmask}',
        ]

    choice2 = input('Do you want INBOUND? (YES or NO): ').lower()
    a = 'in' if choice2 == 'yes' else 'out'
  config_commands += [
        f"int {interface}",
        f"ip access-group {n} {a}",
    ]
    
    try:
        device.load_merge_candidate(config="\n".join(config_commands))
        diffs = device.compare_config()
        if diffs:
            print("Proposed configuration changes:")
            print(diffs)
            device.commit_config()
            print("Configuration committed.")
        else:
            print("No configuration changes to commit.")
    except LockError:
        print("Configuration lock error.")
    except UnlockError:
        print("Configuration unlock error.")
    except Exception as e:
        print(f"Error configuring ACL: {e}")
    finally:
        device.discard_config()
          #--------------------PORT SECURITY----------------#
def port_security(ip, choice1, interface, stickyLearning, max, Mac, username, password):
    """
    Configure port security on a network device using NAPALM.

    :param ip: IP address of the network device.
    :param choice1: 'shut', 'restrict', or 'protect' for different port security options.
    :param interface: Name of the interface to configure.
    :param stickyLearning: Sticky MAC address for port security.
    :param max: Maximum number of allowed MAC addresses.
    :param Mac: Additional MAC address to allow (optional).
    :param username: Username for device login.
    :param password: Password for device login.
    """

    device = get_napalm_connection(ip, username, password)

    if choice1 == 'shut':
        choice2 = input('Do you want to configure the port in Access or Trunk? ').lower()
        config_commands = [
            f"interface {interface}",
            f"switchport port-security mac-address {stickyLearning}",
            f"switchport port-security maximum {max}",
            "errdisable recovery cause psecure-violation",
        ]
        if Mac is not None and Mac != "":
            config_commands.append(f"switchport port-security mac-address {Mac}")

    elif choice1 == 'restrict':
        config_commands = [
            f"interface {interface}",
            f"switchport port-security maximum {max}",
            f"switchport port-security mac-address {stickyLearning}",
            f"switchport port-security maximum {max}",
            "switchport port-security violation restrict",
        ]
        if Mac is not None and Mac != "":
            config_commands.append(f"switchport port-security mac-address {Mac}")

    elif choice1 == 'protect':
        config_commands = [
            f"interface {interface}",
            f"switchport port-security maximum {max}",
            f"switchport port-security mac-address {stickyLearning}",
            "switchport port-security violation protect",
        ]
        if Mac is not None and Mac != "":
            config_commands.append(f"switchport port-security mac-address {Mac}")

    try:
        device.load_merge_candidate(config="\n".join(config_commands))
        diffs = device.compare_config()

        if diffs:
            print("Proposed configuration changes:")
            print(diffs)
            device.commit_config()
            print("Configuration committed.")
        else:
            print("No configuration changes to commit.")
    except LockError as e:
        print(f"Configuration lock error: {e}")
    except UnlockError as e:
        print(f"Configuration unlock error: {e}")
    except Exception as e:
        print(f"Error configuring Port security: {e}")
    finally:
        device.discard_config()





def arp_inspection(ip, vlan_number, arp_inspection_type, trusted_interface, rate_limit, interval,username,password):
    device = get_napalm_connection(ip,username,password)
 config_commands = [
        f"ip arp inspection vlan {vlan_number}",
        "errdisable recovery cause arp-inspection",
        f"inspection ip arp {arp_inspection_type}",
        f"interface {trusted_interface}",
        "ip arp inspection trust",
        f"ip arp inspection limit rate {rate_limit} interval {interval}",
    ]
    
    try:
        device.load_merge_candidate(config="\n".join(config_commands))
        diffs = device.compare_config()

        if diffs:
            print("Proposed configuration changes:")
            print(diffs)
            device.commit_config()
            print("Configuration committed.")
        else:
            print("No configuration changes to commit.")
    except LockError:
        print("Configuration lock error.")
    except UnlockError:
        print("Configuration unlock error.")
    except Exception as e:
        print(f"Error configuring ARP inspection: {e}")
    finally:
        device.discard_config()

def main():
    try:
      while True:
        print("\n========== Security Configuration Menu ==========")
        print("1. ACL Configuration")
        print("2. Port security Configuration")
        print("3. DHCP Snooping configuration")
        print("4. ARP INSPECTION CONFIGURATION")
        print("5. DOS ATTACK PREVENTION")
        print("6.EXIT")
        print("===============================================")

        choice = input("Enter the number of your choice: ")
        username = input("Enter the username: ")
        password=getpass.getpass('Enter the password: ')
 
          if choice == '1':
            choice = input("Do you want to configure standard ACL, extended ACL, or CRUD? ").lower()

            if choice == "standard":
                acl_info = construct_STANDARDACL_LIST()
                for acl_data in acl_info.values():
                    for i in  acl_data['neighbors']:
                        configure_STANDARDacl(acl_data['ip'],i, acl_data['DENY'], acl_data['wildMask'], acl_data['INTERFACE'],username,password)

            elif choice == "extended":
                acl_info = construct_ExtendedACL_LIST()
                for  acl_data in acl_info.values():
                    for i in acl_data['SOURCEP']:
                        for j in acl_data['DESTINATIONP']:
                            for a in acl_data['SOURCED']:
                                for b in acl_data['DESTINATIOND']:
                                    configure_extended_acl(acl_data['ip'], i, acl_data['wildMask1'], j, acl_data['wildMask2'],
                                                 a, acl_data['wildMask3'], b, acl_data['wildMask4'], acl_data['protocol'], acl_data['INTERFACE'],username,password)

            elif choice == "crud":
                ip = input('Enter the IP address of the device: ')
                CrudACL(ip,username,password)

            else:
                print("Invalid choice. Please choose 'standard', 'extended', or 'crud'.")
        if choice=='2':
              for switch in switches:
              port_security(
            switch['ip'],
            switch['choice1'],
            switch['interface'],
            switch['stickyLearning'],
            switch['max'],
            switch['Mac'],
            switch['username'],
            switch['password']
        )
        if choice=='3': 
            ip = input("Enter the device IP address: ")
            number_vlan = input("Enter the VLAN number: ")
            interface = input("Enter the interface name: ")
            rate_limit = input("Enter the rate limit: ")
            dhcp_rate_time = input("Enter the DHCP rate time: ")
 dhcp_snooping(ip, number_vlan, interface, rate_limit, dhcp_rate_time,username,password)

        if choice=='4': 
             ip = input("Enter the device IP address: ")
             vlan_number = input("Enter the VLAN number: ")
             arp_inspection_type = input("Enter the ARP inspection type (src-mac/dst-mac/ip): ")
             trusted_interface = input("Enter the trusted interface name: ")
             rate_limit = input("Enter the rate limit: ")
             interval = input("Enter the interval in seconds: ")
    
             arp_inspection(ip, vlan_number, arp_inspection_type, trusted_interface, rate_limit, interval,username,password)


    except KeyboardInterrupt:
        print("\nExiting the scrip.")




if __name__ == "__main__":
    main()



