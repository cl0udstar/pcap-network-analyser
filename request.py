"""
    The module gets the requests from the pcap file which have
    .jpg, .jpeg, .png or .gif file extensions

    Prints the whole url and the filename that has any of the extensions.
"""

# Importing the required modules
import os  # OS used to split up the filename from the whole url
import re  # Using the re module to find the emails using a regex paterns
import dpkt  # DPKT to analyse the type of request (port number) and get information of the request


GREEN = '\33[32m'
END = '\33[0m'
RED = '\33[31m'
YELLOW = '\33[33m'


def get_email(pcapfile):
    """
        Start of the email getter function.
        The pcap file is parsed from the 'infogathermodule'
        (used to open the file in a different encoding format)
    """
    # Store the TO emails in the first nested list and the FROM emails in the second nested list
    emails_list = [[], []]

    try:
        # Open the pcap file in a different encoding (latin-1)
        with open(pcapfile, "r", encoding=("latin-1")) as pcapfile_contents:
            file_contents = pcapfile_contents.read()

            # Status information message
            print(f"{GREEN}File{END} {pcapfile} {GREEN}read successfully!{END}")

        # Extracting the emails with other contents linked to them
        emails_to_raw = re.findall(r'\bTO: .[\w\._-]+@[\w\._-]+.[\w\._-]+', file_contents)
        emails_from_raw = re.findall(r'\bFROM: .[\w\._-]+@[\w\._-]+.[\w\._-]+', file_contents)

        if not emails_to_raw or not emails_from_raw:
            print(f"{YELLOW}No emails found!{END}")
        else:
            # Store only the unique emails into a list using the dictionary built-in functions
            unique_email_to = list(dict.fromkeys(emails_to_raw))
            unique_email_from = list(dict.fromkeys(emails_from_raw))

            # Clearing the emails from any un-needed characters (store only the email part in lists)
            for email in unique_email_to:
                emails_list[0].append(email.replace('TO: <', ''))
            for email in unique_email_from:
                emails_list[1].append(email.replace('FROM: <', ''))

            print(f"{GREEN}Emails extracted successfully!{END}\n")  # Status information message

            # Print the emails when the function is call in the main module (infogathermodule)
            for item in emails_list[0]:
                print(f"{YELLOW}TO:{END} {item}")

            for item in emails_list[1]:
                print(f"{YELLOW}FROM:{END} {item}")
        pcapfile_contents.close()  # Close the file after use
    except IOError:
        print(f"{RED}Could not read the file!{END} {0}".format(IOError.errno))

    return emails_list


def get_request(eth_list):
    """
        Function get the request part from the ethernet frame
        Loops through every packet in the list and only takes the ones that have the file extensions
    """
    print(f"{GREEN}Extracting requests...{END}\n")  # Status information message
    request_count = 0
    # Loop through the the ethernet frame to get each packet analysed
    for packet in eth_list:
        try:  # Exception handling
            request = dpkt.http.Request(packet.data)

            # Check if the port is 80 (thats for http requests)
            if packet.dport == 80:
                # Check the uri if it ends with .jpg, .jpeg, .png or .gif
                if (request.uri.endswith(".jpg") or
                    request.uri.endswith(".jpeg") or
                    request.uri.endswith(".png") or
                    request.uri.endswith(".gif")):

                    # Print the full url if the extensions are found
                    print(f"🌐 Full URL: http://{request.headers['host']}{(request.uri)}")
                    # Print only the filename
                    print(f"📂 Filename: {os.path.basename(request.uri)}\n")
                    request_count +=1

            # Check if the port is 443 (thats for https requests)
            elif packet.dport == 443:
                if (request.uri.endswith(".jpg") or
                    request.uri.endswith(".jpeg") or
                    request.uri.endswith(".png") or
                    request.uri.endswith(".gif")):

                    print(f"🌐 Full URL: https://{request.headers['host']}{(request.uri)}")
                    print(f"📂 Filename: {os.path.basename(request.uri)}\n")
                    request_count +=1

        # Exception handling (when an error is encountered, then continue running the program)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, AttributeError):
            continue

    # Check if no URL was found
    if request_count == 0:
        print(f"{YELLOW}No requests found!{END}")
