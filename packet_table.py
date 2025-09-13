"""
    Creating the table with the packet types information.
    Using datetime module to convert the timestamp of each packet.
    Storing only the first and the last timestamp of each type of packet.
    Calculating the average length of each packet type.
"""
from datetime import datetime  # Datetime module is used to convert the packet timestamps
from tabulate import tabulate

BLUE = '\33[34m'
VIOLET = '\33[35m'
GREEN = '\33[32m'
RED = '\33[31m'
END = '\33[0m'

# List that stores the average length for each packet type
mean_list = [[], [], [], [], []]


def calculate_packet_mean(udp_count, tcp_count, igmp_count, icmp_count, raw_count, total_len):
    """
        Function to calculate the packet mean
    """
    # Condition to determine if the total length of each packet type is not 0,
    # then it could execute the math for calculating the average
    if total_len[0] != 0:
        # Index 0 is the first nested list which stores the average for UDP packets
        mean_list[0] = round(total_len[0]/udp_count, 3)
    else:
        # If total packet length is 0, then store the mean as 0 in the list
        mean_list[0] = '0'

    # Same approach is used for the other packet types
    if total_len[1] != 0:
        mean_list[1] = round(total_len[1]/tcp_count, 3)
    else:
        mean_list[1] = '0'

    if total_len[2] != 0:
        mean_list[2] = round(total_len[2]/igmp_count, 3)
    else:
        mean_list[2] = '0'

    if total_len[3] != 0:
        mean_list[3] = round(total_len[3]/icmp_count, 3)
    else:
        mean_list[3] = '0'

    if total_len[4] != 0:
        mean_list[4] = round(total_len[4]/raw_count, 3)
    else:
        mean_list[4] = '0'


def create_packet_table(udp_count, tcp_count, igmp_count, icmp_count, raw_count, packets_list):
    """
        Function to create the actual table with all the info
    """
    # Using the count for each packet type from the 'infogathermodule'
    # to determine whether the count is 0 or greater
    # If its greater, then the first and last timestamps are extracted from the each packet type
    # Then converted to an actual date and time value
    if udp_count > 0:
        udp_first_ts = datetime.fromtimestamp(packets_list[0][0][0])
        udp_last_ts = datetime.fromtimestamp(packets_list[0][0][-1])
    else:
        # If the packet count is 0, then the value in the table will be as 'no value'
        udp_first_ts, udp_last_ts = "no value", "no value"

    if tcp_count > 0:
        tcp_first_ts = datetime.fromtimestamp(packets_list[1][0][0])
        tcp_last_ts = datetime.fromtimestamp(packets_list[1][0][-1])
    else:
        tcp_first_ts, tcp_last_ts = "no value", "no value"

    if igmp_count > 0:
        igmp_first_ts = datetime.fromtimestamp(packets_list[2][0][0])
        igmp_last_ts = datetime.fromtimestamp(packets_list[2][0][-1])
    else:
        igmp_first_ts, igmp_last_ts = "no value", "no value"

    if icmp_count > 0:
        icmp_first_ts = datetime.fromtimestamp(packets_list[3][0][0])
        icmp_last_ts = datetime.fromtimestamp(packets_list[3][0][-1])
    else:
        icmp_first_ts, icmp_last_ts = "no value", "no value"

    if raw_count > 0:
        raw_first_ts = datetime.fromtimestamp(packets_list[4][0][0])
        raw_last_ts = datetime.fromtimestamp(packets_list[4][0][-1])
    else:
        raw_first_ts, raw_last_ts = "no value", "no value"

    # Get all the needed values in a list that will print the table at a later stage
    table_data = [
        [f"{BLUE}UDP{END}", f"{BLUE}{udp_count}{END}",
        f"{BLUE}{udp_first_ts}{END}", f"{BLUE}{udp_last_ts}{END}",
        f"{BLUE}{mean_list[0]}{END}"],

        [f"{VIOLET}TCP{END}", f"{VIOLET}{tcp_count}{END}",
        f"{VIOLET}{tcp_first_ts}{END}", f"{VIOLET}{tcp_last_ts}{END}",
        f"{VIOLET}{mean_list[1]}{END}"],

        ["IGMP", igmp_count,
        igmp_first_ts, igmp_last_ts,
        mean_list[2]],

        ["ICMP", icmp_count,
        icmp_first_ts, icmp_last_ts,
        mean_list[3]],

        ["RAW", raw_count,
        raw_first_ts, raw_last_ts,
        mean_list[4]]
    ]

    # Set the column names
    column_names = ["Packet Types", "Packet Count",
                    "First Timestamp", "Last Timestamp",
                    "Packet Mean"]

    print(f"{GREEN}Table created successfully!{END}\n")  # Status information message
    # Using tabulate module to create the table
    print(tabulate(table_data, headers = column_names, tablefmt = "mixed_grid"))


def ip_address_pairs(ip_pairs_list):
    """
        Function which gets the IPs from the 'ip_pairs_list'
        and stores them in a dictionary
        Also counting them at the same time
    """
    # Create the dictionary
    packets_dict = {ip_count:ip_pairs_list.count(ip_count) for ip_count in ip_pairs_list}

    print(f"{GREEN}IPs extracted! Now counting...{END}\n")

    # Loop to go through the items of the dictionary
    # Sort them from the highest packets sent to the lowest
    for key, value in sorted(packets_dict.items(), key = lambda item: item[1], reverse=True):
        print(f"{key} -- {RED}{value}{END}")

    return packets_dict
