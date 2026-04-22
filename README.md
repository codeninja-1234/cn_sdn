
# SDN Firewall using POX Controller (Mininet)


#Author:
#Name: Shruti Choudhary
# SRN: PES1UG24AM271

## Problem Statement
Implement an SDN-based firewall using Mininet and POX controller that demonstrates:
- Controller–switch interaction
- Flow rule (match–action) design
- Selective traffic filtering
- Network behavior observation

## Objective
- Block traffic from h1 → h2  
- Allow traffic from h2 → h1  
- Demonstrate directional firewall behavior  
- Show flow rule installation using OpenFlow  

## Topology
- 1 Switch (s1)  
- 2 Hosts:
  - h1 → 10.0.0.1  
  - h2 → 10.0.0.2  

## Technologies Used
- Mininet  
- POX Controller  
- OpenFlow  

## Setup & Execution

### Clean previous runs
sudo mn -c  
sudo fuser -k 6633/tcp  

### Start Controller
cd ~/pox  
./pox.py misc.firewall  

### Start Mininet
sudo mn --topo single,2 --controller remote,ip=127.0.0.1,port=6633  

## Testing

### Blocked Traffic
h1 ping h2  
Result: 100% packet loss  

### Allowed Traffic
h2 ping h1  
Result: Successful communication  

## Flow Table
Run in separate terminal:
sudo ovs-ofctl dump-flows s1  

## Working Principle
- Switch sends packets to controller (packet_in)  
- Controller applies match–action rules  
- Flow rules installed dynamically  
- Firewall blocks specific traffic  

## Conclusion
Successfully implemented SDN firewall with directional traffic control.
