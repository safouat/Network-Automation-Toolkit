from napalm import get_network_driver
from napalm.base.exceptions import LockError, UnlockError
           # This code is not finished yet #
# ----------ACL AUTOMATION------------------ #
# ----PORT SECURITY IMPLEMENTATION---------- #
# ----DHCP SNOOPING IMPLEMENTATION-------- #
# -----DYNAMIC ARP INSPECTION------------ #
def get_napalm_connection(ip_address):
    driver = get_network_driver('ios')
    device = driver(hostname=ip_address, username="safouat", password="cisco")
    
    try:
        device.open()
    except Exception as e:
        print(f"Error connecting to {ip_address}: {e}")
        return None
    
    return device

def configure_STANDARDacl(ip,permitADD, DenyADD, wildmask, interfaceACL):
    choice1 = input('Do you want to use numbered ACL? (YES or NO): ').lower()
    device = get_napalm_connection(ip)
    if choice1 == 'yes':
        n = int(input('Enter the number of ACL: '))  # n should be in 100-199 or 2000-2699
        config_commands = [
            f"access list {n} permit {permitADD}",
            f"access list {n} deny {DenyADD} {wildmask}",
            f"access list {n} permit any",
        ]
    else:
        n = input('Enter the name of ACL: ')
        nuber = int(input('Enter the entry of ACL: '))
        config_commands = [
            f"access list {n}",
            f"{nuber} permit {permitADD}",
            f"{nuber} deny {DenyADD} {wildmask}",
            f"{nuber} permit any",
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

            router_graph[name] = {'ip': ip, 'neighbors': neighbor_list, 'wildMask': wildMask, 'DENY': deny, 'INTERFACE': INT}
            otherACL = input("\nDo you want to add another ACL? Answer with 'y' or 'n': ").lower()
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return ACL_LIST

#---------------ACL CRUD---------------#
def CrudACL(ip):
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
            
            
            portocol= input('Enter the portocol:UDP,TCP,ICMP,EIGRP,OSPF ')
            INT=input('Enter the interface on wich the ACL WILL BE CONFIGURED ')
            

            ACL_LIST[name] = {'ip': ip, 'SOURCEP': SOURCEP, 'wildMask1': wildMask1, 'DESTINATIONP': DESTINATIONP,'wildMask2': wildMask2,'SOURCED': SOURCED, 'wildMask3': wildMask3, 'DESTINATIOND': DESTINATIOND,'wildMask4': wildMask4, 'INTERFACE': INT}
            otherACL = input("\nDo you want to add another ACL? Answer with 'y' or 'n': ").lower()
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return  ACL_LIST
            
                  


def configure_extended_acl(ip,source_permit, source_wildmask, dest_permit, dest_wildmask, source_deny, source_deny_wildmask, dest_deny, dest_deny_wildmask, protocol, interface):
    choice1 = input('Do you want to use numbered ACL? (YES or NO): ').lower()
    device = get_napalm_connection(ip)
    if choice1 == 'yes':
        n = int(input('Enter the number of ACL: '))  # n should be in 100-199 or 2000-2699
        config_commands = [
            f"access list {n} permit {protocol} {source_permit} {source_wildmask} {dest_permit} {dest_wildmask}",
            f"access list {n} deny {protocol} {source_deny} {source_deny_wildmask} {dest_deny} {dest_deny_wildmask}",
           
        ]
    else:
        n = input('Enter the name of ACL: ')
       
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

def main():
    try:
        while True:
            choice = input("Do you want to configure standard ACL, extended ACL, or CRUD? ").lower()

            if choice == "standard":
                acl_info = construct_STANDARDACL_LIST()
                for acl_data in acl_info.values():
                    configure_STANDARDacl(acl_data['ip'], acl_data['permitADD'], acl_data['DenyADD'], acl_data['wildMask'], acl_data['INTERFACE'])

            elif choice == "extended":
                acl_info = construct_ExtendedACL_LIST()
                for acl_name, acl_data in acl_info.items():
                    configure_extended_acl(acl_data['ip'], acl_data['SOURCEP'], acl_data['wildMask1'], acl_data['DESTINATIONP'], acl_data['wildMask2'],
                                           acl_data['SOURCED'], acl_data['wildMask3'], acl_data['DESTINATIOND'], acl_data['wildMask4'], acl_data['portocol'], acl_data['INTERFACE'])

            elif choice == "crud":
                ip = input('Enter the IP address of the device: ')
                CrudACL(ip)
                
            else:
                print("Invalid choice. Please choose 'standard', 'extended', or 'crud'.")

    except KeyboardInterrupt:
        print("\nExiting the script.")

if __name__ == "__main__":
    main()

