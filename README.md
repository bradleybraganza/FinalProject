# FinalProject
FTP SnifferProgram

File Transfer Protocol (FTP) is used to transfer files from a host to another host over a network, such as the internet. This connection between client and server can sometimes be authenticated through a sign-in protocol.  The program that we created will be used to exploit the vulnerabilities of FTP. We plan to do is by implementing packet sniffing into our program that will target usernames and passwords. It will check to make sure that the traffic we are targeting is specifically FTP traffic. From there, we will have the program store the usernames and passwords into a python list. Additionally, we will use a GUI to allow users to easily control the program. 
Prerequisites:
The following program requires python, Tkinter and scapy to run. It is advised to have these installed before you run these files. 
To get scapy use the following commands on the terminal:
sudo apt install python-pip
pip install scapy

To get Tkinter: 
sudo apt install python-tk 
Installing: 
Clone the repository and save it on your desktop. It contains a folder named Server Files and a python readable file called sniffV2.py. These are your ready to use programs. 
Running: 
Open up a terminal, and execute the following commands: 
cd Desktop
cd FinalProject
python sniffV2.py

When you run this, a window should pop up asking you to enter an interface that you would like to start sniffing. Enter ‘lo’ which stands for local network, since we will be sniffing on a made local server that you installed from these files. Once it starts to run successfully, open up a second terminal. In that terminal type: 
cd Desktop
cd FinalProject
cd ServerFiles
python ftpServer.py

If successful, it should start running the server locally. Next, open your internet browser (chrome, firefox, safari) and type in the following address : ftp://127.0.0.1:2121. Remember 2121 is the port number you will sniff on, so do not change it. When the webpage runs, you will be asked to enter a username and password. We have predesignated two usernames in the program, g7 and user. For g7 the password is g7, and for ‘user’ it is 12345. When you enter them, your sniffer program  should successfully catch these credentials and display it on the screen. 

Built With: 
Scapy: The packet sniffing library
Tkinter: The GUI design library
Authors 

Bradley Braganza 
David May
Zubair Matani 
Vincent Sosa




Acknowledgements
FTP Server Files: https://github.com/giampaolo/pyftpdlib
