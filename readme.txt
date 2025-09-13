Program description:
	The program awaits for input from the user about the .pcap file to open. If the file is found, the program continues and opens it. 
	Analyses it by storing key information from the ethernet frame about each packet that is stored in the file. 
	Further it goes and asks the user to select an option from the menu. (The menu consists of 7 points, where each point displays unique output 
		with the information stored earlier)


In order for this program to work some modules are used to make the pcap file analysis functional and easier.
The modules used are:
	dpkt
	socket
	tabulate
	networkx
	matplotlib

If any of these modules are not installed, using pip install will get these sorted.