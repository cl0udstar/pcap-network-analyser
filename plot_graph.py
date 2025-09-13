"""
    This module generates a graph that contains details about how
    the packets are sent from one ip to another
"""

# Import the necessary modules
import os  # Using os module to print the directory and the pcap filename
import networkx as nx  # Networkx is used to generate the graph
import matplotlib.pyplot as plt  # Matplotlib is used to plot the actual graph
import matplotlib as mpl

BLUE = '\33[34m'
GREEN = '\33[32m'
RED = '\33[31m'
END = '\33[0m'


def create_network_graph(ip_src_list, ip_dst_list, pcapfile):
    """
        Function which is responsible for the plotting of the n etwork graph
    """
    # Telling the networkx module which type of graph is needed
    graph = nx.DiGraph()

    # Loop through the source ip list to create the nodes
    for node_ip in ip_src_list:
        graph.add_node(node_ip)

    # Loop through both lists of source and destination IPs
    # create the link bettween them (the edges)
    for (item, item2) in zip(ip_src_list, ip_dst_list):
        graph.add_edge(item, item2)

    # Colours for different packets sent
    colors = ['black', 'blue', 'green', 'red', 'orange']
    plt.figure(figsize=(20, 10))  # Creates a figure object

    # Setting the position of the graph
    graph_pos = nx.spring_layout(graph, iterations=4, weight='string', scale=1, dim=2, seed=150)

    # Add the nodes to the graph
    nx.draw_networkx_nodes(graph, graph_pos, node_color='red', node_size=250, alpha=0.5)

    # Add the edges to the graph
    nx.draw_networkx_edges(graph,
                        graph_pos,
                        edge_color=colors,
                        connectionstyle='arc3, rad=0.2',
                        arrowstyle='->',
                        arrowsize=7,
                        alpha=0.2)

    # Add the ip addresses on the nodes
    nx.draw_networkx_labels(graph, graph_pos, font_size=5, font_family='sans-serif')

    # Save the graph generated as a .png file (get the name of the file inputed)
    plt.savefig(f'{os.path.splitext(pcapfile)[0]}_net_graph.png')
    plt.show()  # Show the graph

    # Status information messages
    print(f"{GREEN}Packet graph generated!{END}")
    print(f"\n{RED}Counting the number of nodes and edges used...{END}\n")

    # Built-in function to count the number of nodes and edges
    print("Nodes used:", graph.number_of_nodes())
    print("Edges used:", graph.number_of_edges())

    # Status information message
    print(f"\n{GREEN}Graph saved as network_graph.png in current working directory:{END}")
    print(f"{os.getcwd()}")


def create_line_chart(ts_list, pcapfile):
    """
        First and last timestamp of all the packets from the pcap file are used.
        Calculates the interval between the first and last timestamp.
        Counts the number of packets in each interval.
        The interval variable is modular, meaning the is easily changable.
        Displays the line chart at the end with all the data gathered.
    """
    # Set the variable to true (this will be true until changed to false)
    choice_check = True

    # While loop to validate the input from the user
    while choice_check:
        # Store the input as a variable
        choice = str(input(f"Would you like add custom intervals (default 70)? {BLUE}(y/n){END} "))
        if choice == 'y':  # Check if the input is y
            # If y, then ask the user the amount of intervals it wants
            intervals = int(input("Enter a number of intervals: "))
            choice_check = False  # Set the choice_check to false (this exits the while loop)
        elif choice == 'n':
            intervals = 70  # If the input is n, then a default value of intervals is set
            choice_check = False  # Set the choice_check to false (this exits the while loop)
        else:
            # If the input is not y nor n, keep looping
            print(f"{RED}Enter y or n!{END}")

    # Calculate the timeframe using the first and the last timestamps
    timeframe = ts_list[-1] - ts_list[0]

    # Calculate how much one interval would be
    one_interval = timeframe / intervals

    # Create the list for storing the packet count during each interval
    packets = []

    # Store the first timestamp in a variable
    ts_start = ts_list[0]
    packet_count = 0  # Set the packet count to 0
    packets.append(packet_count)  # Add zero to the packet count list

    # Part of code reference:
    # https://codereview.stackexchange.com/questions/214857/split-a-number-into-equal-parts-given-the-number-of-parts
    # Create the for loop which will loop through the intervals
    for _ in range(intervals):
        # Set the step to the starting timestamp adding the interval value
        step = ts_start + one_interval

        # Another for loop to go through the timestamp list
        for time_s in ts_list:
            # Validate each timestamp
            if ts_start <= time_s <= step:
                packet_count += 1  # Add one to the packet count when a timestamp is in the range
        packets.append(packet_count)
        packet_count = 0  # Set the packet count to 0 after the loop

        # Set the new start timestamp
        ts_start += one_interval

    # Calculate the average packets that are sent
    mean = len(ts_list) / intervals

    # Set the width of the packets graph line
    mpl.rcParams['lines.linewidth'] = 1.5

    # Plot the packets from intervals
    plt.plot(packets, label='Packets', color='black')

    # Plot the average packet send line
    plt.axhline(mean, label='Mean', linestyle='--', color='red')
    plt.title("Number of packets line chart")  # Add the title of the graph
    plt.ylabel('Packets')  # Set the y values label
    plt.xlabel('Intervals')  # Set the x values label
    plt.legend()  # Display the information about each line

    # Save the graph generated as a .png file (get the name of the file inputed)
    plt.savefig(f'{os.path.splitext(pcapfile)[0]}_line_chart.png')
    plt.show()  # Show the graph while the program runs

    # Status information message
    print(f"\n{GREEN}Graph saved as line_chart.png in current working directory:{END}")
    print(f"{os.getcwd()}")
