"""
    The main function of this module is to extract
    specific data from the pcap file
"""
# Import the modules that are required to execute certain commands
import os
import socket  # the socket module is used to decode the ip adderesses from hex to decimal
import dpkt  # analyses pcap files (gets info about ethernet, packets, IPs, timestamps, etc.)
from tabulate import tabulate  # tabulate module helps to build the border for the menu
import packet_table as pt  # module which creates the table with packet info
import request  # gets information from requests
import plot_graph  # creates the graph for packets (uses IPs from the 'ippairsmodule')

# List created to store the packets of each type (udp, tcp, igmp, icmp, raw)
# from the pcap file and their timestamps
packets_list = [[[]], [[]], [[]], [[]], [[]]]

GREEN = '\33[32m'
RED = '\33[31m'
END = '\33[0m'


def main():
    """
        Main function. Helps run the other modules and also the menu at the start
    """
    # Variables that help store the number of packets of each type
    udp_count = 0
    tcp_count = 0
    igmp_count = 0
    icmp_count = 0
    raw_count = 0

    # Variables which holds the total length of each packet types
    udp_len_total = 0
    tcp_len_total = 0
    igmp_len_total = 0
    icmp_len_total = 0
    raw_len_total = 0

    # List that store different values from the pcap file
    eth_list = []
    ts_list = []
    ip_src_list = []
    ip_dst_list = []
    ip_pairs_list = []
    total_len = []

    # Exception handling that looks for any error with the pcap file (FileNotFoundError)
    file_check = True
    while file_check:
        try:
            pcapfile = str(input("Please enter a file to analyse: "))
            if os.path.isdir(pcapfile):
                print(f"{RED}The input{END} {pcapfile} {RED}is a directory!{END}")
            else:
                open_file = open(pcapfile, "rb")  # Open and read the pcap file (in binary)
                file_check = False  # Set the while loop to false when the file is right

                # Status information messages
                print(f"\n{RED}Reading file...{END}")
                print(f"{GREEN}File{END} {pcapfile} {GREEN}read successfully{END}\n")

                # Using the dpkt module to read a pcap file and store the contents in a variable
                pcap = dpkt.pcap.Reader(open_file)

                # Loop through the pcap file contents
                for time_s, buf in pcap:
                    # Store ethernet contents of a packet into a variable
                    # (changes every time until the file end is reached)
                    eth = dpkt.ethernet.Ethernet(buf)
                    ts_list.append(time_s)
                    ip_address = eth.data  # Store only the packet IP contents
                    packet = ip_address.data  # Store the contents of a packet at a time

                    eth_list.append(packet)  # Append the contents of each packet in a list

                    src_ip = socket.inet_ntoa(ip_address.src)  # Decode the source ip
                    ip_src_list.append(src_ip)  # Add the decoded version of the source ip to list
                    dst_ip = socket.inet_ntoa(ip_address.dst)  # Decode the destination ip
                    ip_dst_list.append(dst_ip)  # Add decoded version of the destination ip to list

                    packets = (f"{src_ip} --> {dst_ip}")  # Group source and destination IPs
                    # Store the grouped IPs in a list
                    # (used to count the packets sent from each ip address)
                    ip_pairs_list.append(packets)

                    # Analyse each packet type (udp, tcp, igmp, icmp and raw)
                    if type(packet) == dpkt.udp.UDP:
                        # Append the upd packets to the first nested list in the packets_list
                        packets_list[0].append(packet)

                        # Add the upd packets timestamp to the first nested list in the packets_list
                        packets_list[0][0].append(time_s)
                        udp_count += 1  # Count the number of udp packets
                        packet_len = len(buf)  # Get the length of of each udp packet

                        # Calculate the total length of all udp packets
                        # (this is used for the mean calculation)
                        udp_len_total = udp_len_total + packet_len

                    # Same procedure is used for the rest of the packet types
                    elif type(packet) == dpkt.tcp.TCP:
                        packets_list[1].append(packet)
                        packets_list[1][0].append(time_s)
                        tcp_count += 1
                        packet_len = len(buf)
                        tcp_len_total = tcp_len_total + packet_len

                    elif type(packet) == dpkt.igmp.IGMP:
                        packets_list[2].append(packet)
                        packets_list[2][0].append(time_s)
                        igmp_count += 1
                        packet_len = len(buf)
                        igmp_len_total = igmp_len_total + packet_len

                    elif type(packet) == dpkt.icmp.ICMP:
                        packets_list[3].append(packet)
                        packets_list[3][0].append(time_s)
                        icmp_count += 1
                        packet_len = len(buf)
                        icmp_len_total = icmp_len_total + packet_len

                    else:
                        packets_list[4].append(packet)
                        packets_list[4][0].append(time_s)
                        raw_count += 1
                        packet_len = len(buf)
                        raw_len_total = raw_len_total + packet_len

                # Append the totals in a list
                total_len.append(udp_len_total)
                total_len.append(tcp_len_total)
                total_len.append(igmp_len_total)
                total_len.append(icmp_len_total)
                total_len.append(raw_len_total)

                # Call the mean calculation function
                pt.calculate_packet_mean(udp_count, tcp_count, igmp_count, icmp_count, raw_count, total_len)

                # Start of the menu system
                print("Please choose an option from the menu below!")
                menu()

                choice = input("Enter the choice: ")
                # Seven choice given. When an option is called, the specified function is executed
                while choice != "7":
                    if choice == "1":
                        print(f"{RED}Creating packet table...{END}")  # Status information message
                        # Call the table creation function. (holds data about each packet type)
                        pt.create_packet_table(udp_count, tcp_count, igmp_count, icmp_count, raw_count, packets_list)

                    elif choice == "2":
                        print(f"{RED}Extracting unique emails from the packets...{END}")
                        # Call the email finder function
                        request.get_email(pcapfile)

                    elif choice == "3":
                        print(f"{RED}Analysing requests from packets...{END}")
                        # Call the request analyser function
                        request.get_request(eth_list)

                    elif choice == "4":
                        print(f"{RED}Exctracting IPs...{END}")
                        # Call the ip dictionary function
                        pt.ip_address_pairs(ip_pairs_list)

                    elif choice == "5":
                        print(f"{RED}Generating the packet graph...{END}")
                        # Call the graph plotting function
                        plot_graph.create_network_graph(ip_src_list, ip_dst_list, pcapfile)

                    elif choice == "6":
                        # Call the line chart plotting function
                        plot_graph.create_line_chart(ts_list, pcapfile)

                    else:
                        print(f"{RED}The option is not valid!{END}")
                        print("Choose something between 1 and 7")
                    print()
                    menu()
                    choice = input("Enter the choice: ")

                # Terminating the program if 7 is chosen
                print(f"{RED}Exiting...{END}")
                print("Thanks for using me and until next time, Peace ✌️")

                open_file.close()  # Close the pcap file
        except FileNotFoundError:
            print(f"{RED}No such file exists:{END} {pcapfile}")
        except IOError:
            print(f"{RED}Could not read the file!{END} {0}".format(IOError.errno))
        except ValueError:
            print(f"{RED}File type different than required! (.pcap needed){END}")

    return pcapfile


def menu():
    """
        The menu contents function
    """
    # Variable which holds the menu options
    table_data = [
        ["1. Summarised version of the packet capture"],
        ["2. Email addresses used for data transfer"],
        ["3. URLs and filenames"],
        ["4. IP address pairs (sender -> destination)"],
        ["5. Network graph"],
        ["6. Number of packets line chart"],
        ["7. Exit"]
    ]

    # Print the menu using the tabulate module
    print(tabulate(table_data, tablefmt = "rounded_outline"))
