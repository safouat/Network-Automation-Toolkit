# Network-Automation-Toolkit-Simplifying-Network-Management-and-Security
The provided Network Automation Toolkit illustrates the utilization of the SSH connection by using the Netmiko and NAPALM  for automating the configuration of diverse network parameters on Cisco devices. This automation  significantly curtails the need for manual configuration, resulting in accelerated setup times and a marked reduction in the potential for human errors. Consequently, network modifications are executed more swiftly and with heightened precision.in practical real-world scenarios, the code should be executed on the network administrator's own PC to configure and manage the actual network infrastructure.For training purposes, I utilized GNS3 along with a specific network topology. During the training, the code was executed within a network automation environment.

Switch Configuration Menu:
![Screenshot from 2023-08-14 19-01-12](https://github.com/safouat/Network-Automation-Toolkit/assets/120058233/9e188316-85b8-4237-8063-6e10938f4edd)



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




My topology:

![Screenshot from 2023-08-14 19-05-21](https://github.com/safouat/Network-Automation-Toolkit/assets/120058233/32874f3c-6875-40ce-ae6b-303a260efc1b)


