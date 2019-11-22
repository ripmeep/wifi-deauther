# wifi-deauther
A WiFi/Wireless Network Deauthentication attack 
Written in C++ for Linux


__________________________


# What is deauthentication?
A WiFi deauthentication attack is an exploit where an attacker broadcasts a message to an access point to disconnect/disassociate itself from configured devices on the network, dropping the connection of said devices.


__________________________


# How to use


# Compile

    $ g++ wifi-deauther.cpp -o wifi-deauther


# Monitor Mode
You must have a wireless device with monitor mode capabilities otherwise this attack will not work!!!

_Method 1_:
Using the linux commands `ifconfig` and `iwconfig` you can put the device into monitor mode like this:

            $ ifconfig <device name> down
            $ iwconfig <device name> mode monitor
            $ ifconfig <device name> up

    Example $ ifconfig wlan0 down
    Example $ iwconfig wlan0 mode monitor
    Example $ ifconfig <device name> up
    

_Method 2_:
If you have the `aircrack-ng` suite installed, you can put the device into monitor mode like this:

            $ airmon-ng start <device name>
    
    Example $ airmon-ng start wlan0
    
    
# Run

            $ ./wifi-deauther <DEVICE NAME> <NETWORK BSSID>
    Example $ ./wifi-deauther wlan0mon 12:34:56:AB:CD:EF        # You can find a networks BSSID/MAC Address using `airodump-ng` or `iw` 
