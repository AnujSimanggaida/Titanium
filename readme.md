Welcome to the Titanium, a TCP based Port Scanner tool
Right now it is in development
To run simply clone this repo ,change your directory to it
Then run the command below:
python3 titanium.py 192.168.x.xx -s scan_type
replace the x's with the IP address you desire
there are currently only two scans types available
1. TCP connect scanning
2. UDP scanning
Examples Usage:
    python3 titanium.py 192.168.1.1 -s tcp
    python3 titanium.py 192.168.1.1 -s udp
This scans ports 1-65535