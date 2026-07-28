Welcome to the Titanium, a TCP based Port Scanner tool
Right now it is in development
To run simply clone this repo ,change your directory to it

Dependencies:
    Python 3.8+
    Scapy
Usage:
    python3 titanium.py <target ip> [options]
Examples:
    TCP connect Scan:
        python3 titanium.py scanme.nmap.org -p 22,80,443 -s tcp
    UDP scan:
        python3 titanium.py 192.168.1.xxx -p 1-1000 -s udp --timeout 0.5
    Full port range with extra threads:
        python3 titanium.py 10.0.0.5 -p 1-65535 -t 200 -s tcp
    SYN scan:
        sudo python3 titanium.py 10.0.0.5 -p 1-1000 -s syn
![image alt](https://github.com/AnujSimanggaida/Titanium/blob/main/Screenshot_20260728_171406.png)
