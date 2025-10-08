################################################################################    

First of all to use this script you should use Python virtul environment 

1. create venv 
    python3 -m venv ~/nfqueue-venv
    
2. activate
    source ~/nfqueue-venv/bin/activate
    
3. upgrade pip inside venv
    pip install --upgrade pip
    
4. Install NetfilterQueue inside venv
    pip install NetfilterQueue python-iptables
    
5. RUN SCRIPT
    sudo ~/nfqueue-venv/bin/python3 firewall_automation.py
    
################################################################################    

!!! if automation will not work on queue 1, change it to number 2.

!!! you can add unique IPs in WHITELIST array.

################################################################################


to disable firewall, just paste those scripts to terminal

sudo ufw disable
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -X
sudo iptables -t nat -X
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo ufw enable

################################################################################    
