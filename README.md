# Network-Automation-Toolkit-Simplifying-Network-Management-and-Security
The provided Network Automation Toolkit illustrates the utilization of the SSH connection by using the Netmiko and NAPALM  for automating the configuration of diverse network parameters on Cisco devices. This automation  significantly curtails the need for manual configuration, resulting in accelerated setup times and a marked reduction in the potential for human errors. Consequently, network modifications are executed more swiftly and with heightened precision.in practical real-world scenarios, the code should be executed on the network administrator's own PC to configure and manage the actual network infrastructure.For training purposes, I utilized GNS3 along with a specific network topology. During the training, the code was executed within a network automation environment.

Switch Configuration Menu:
![image](https://github.com/safouat/Network-Automation-Toolkit/assets/120058233/f521c8a8-305e-44b9-8e05-355cdd92aae1)




    VLAN Configuration: VLANs (Virtual Local Area Networks) allow you to logically segment your network, enhancing security and manageability by grouping devices based on functions or departments.

    Interface Settings: This option lets you configure individual interfaces on switches, specifying parameters such as IP addresses, subnet masks, and descriptions.

    Dynamic Trunking Protocol (DTP) Configuration: DTP automates the negotiation of trunk links between switches. This setting lets you control whether DTP is enabled or disabled on specific interfaces.

    Port Configuration (Access/Trunk): You can configure ports as access ports (for devices like PCs) or trunk ports (carrying multiple VLAN traffic) to control the flow of network traffic.

    Spanning Tree Protocol (STP) Mode and Parameters: STP prevents loops in Ethernet networks. You can choose different STP modes (like Rapid PVST+, MSTP) and configure parameters for STP convergence and timers.

    STP Convergence Configuration: This option allows you to fine-tune STP convergence settings, ensuring rapid network recovery in case of topology changes.

Router Configuration Menu:

![Screenshot from 2023-08-14 19-03-04](https://github.com/safouat/Network-Automation-Toolkit/assets/120058233/e77f4851-f4a5-4997-be15-e084de4fe743)

    Static Routing Configuration: Configure static routes to manually define paths for network traffic between different subnets or networks.

    RIP Configuration: Set up the Routing Information Protocol (RIP) to enable dynamic routing within your network. RIP exchanges routing information between routers.

    EIGRP Configuration: Configure the Enhanced Interior Gateway Routing Protocol (EIGRP), a Cisco proprietary protocol, for efficient routing and rapid convergence.

    OSPF Configuration: Set up the Open Shortest Path First (OSPF) protocol, a popular link-state routing protocol, to enable efficient routing and adapt to network changes.

    DHCP Configuration: Dynamic Host Configuration Protocol (DHCP) automates the assignment of IP addresses and network configuration to devices, simplifying network management.

    DNS Configuration: Configure Domain Name System (DNS) settings to enable name resolution, allowing users to access resources using domain names rather than IP addresses.

    Loopback Configuration: Configure loopback interfaces, which are virtual interfaces used for management, testing, and routing purposes. Loopbacks provide stability to router functions and can be valuable in network design and troubleshooting.
Security Configuration Menu:
![image](https://github.com/safouat/Network-Automation-Toolkit/assets/120058233/36ee41b4-eda2-48c5-a7f5-cad41c3b92c5)


ACL Configuration:
Access Control Lists (ACLs) are network security features that filter and control incoming and outgoing traffic based on defined rules. ACLs are implemented at routers and switches to permit or deny traffic based on criteria such as source/destination IP addresses, port numbers, protocols, and more. By configuring ACLs, network administrators can enforce security policies, control network access, and mitigate threats by selectively allowing or blocking specific types of traffic.

Port Security Configuration:
Port security is a feature commonly used in Ethernet switches to enhance network security by controlling which devices can connect to a switch port. It involves setting limits on the number of MAC addresses that can be learned on a port, and actions like shutting down or restricting port access when unauthorized devices are detected. Port security helps prevent unauthorized devices from connecting to the network and ensures that only authorized devices can communicate through the switch ports.

ARP Inspection:
ARP Inspection is a security mechanism used to mitigate Address Resolution Protocol (ARP) spoofing attacks in a network. ARP Inspection validates ARP packets to ensure that the MAC addresses in ARP responses match the IP addresses assigned to them. It works by associating trusted interfaces with valid ARP entries and rate-limiting ARP traffic to prevent flooding. By implementing ARP Inspection, networks can prevent attackers from redirecting traffic and enhancing overall security.

DHCP Snooping:
DHCP Snooping is a security feature that safeguards against rogue DHCP servers and prevents unauthorized devices from distributing IP addresses on a network. It involves classifying switch ports as trusted (connected to legitimate DHCP servers) or untrusted (end-user devices), and monitoring DHCP traffic. DHCP Snooping can drop or log DHCP traffic from untrusted sources and create a binding table of valid IP-MAC pairs to prevent address conflicts and IP misuse.

INSTALATION:
# Step 1: Clone the repository
git clone https://github.com/safouat/Network-Automation-Toolkit

# Step 2: Working with a virtual simulator (e.g., GNS3):
# - Navigate to your lab in GNS3.
# - Locate the network automation appliance.
# - Open the terminal within the network automation appliance.


# If you are a network administrator:
# - Copy the content of the specific configuration file you wish to automate.

# If you have administrative privileges, paste the copied content into your terminal and execute the necessary commands.

USAGE:
My topology:
As previously mentioned, run the code on the network automation appliance by copying it using the command 'nano namefile.py'.(namefile is RouterConfig or SwitchConfig or SecurityConfig)
After copying, execute the code using 'python3 namefile.py'. 
This will display the automation options you're looking to automate.
![Screenshot from 2023-08-14 19-05-21](https://github.com/safouat/Network-Automation-Toolkit/assets/120058233/32874f3c-6875-40ce-ae6b-303a260efc1b)


