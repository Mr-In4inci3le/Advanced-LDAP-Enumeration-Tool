import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama for colored output
init(autoreset=True)


# Banner and description
def print_banner():
    print(Fore.GREEN + Style.BRIGHT + """
   _____           _                 _       _          
  |_   _|         | |               (_)     (_)         
    | |  _ __  ___| |_ _ __ ___  _ __ _ _ __  _ ___  ___ 
    | | | '_ \/ __| __| '__/ _ \| '__| | '_ \| / __|/ _ \\
   _| |_| | | \__ \ |_| | | (_) | |  | | | | | \__ \  __/
  |_____|_| |_|___/\__|_|  \___/|_|  |_|_| |_|_|___/\___|
    """ + Fore.CYAN + Style.BRIGHT + """
                 by Invincible                
       Advanced LDAP Enumeration and Attack Tool       
    """ + Fore.YELLOW + Style.NORMAL + """
    Description:
    This tool is designed for advanced LDAP enumeration and attack
    simulations. It retrieves detailed LDAP server information and 
    suggests possible attack vectors based on the gathered data.
    """)


# Initialize LDAP server and connection
def initialize_connection(server_ip, port, username=None, password=None):
    server = Server(server_ip, port=port, get_info=ALL)
    if username and password:
        connection = Connection(server, user=username, password=password, auto_bind=True)
    else:
        connection = Connection(server, auto_bind=True)
    return connection, server


# Print basic server information
def print_server_info(server):
    print(Fore.YELLOW + "\nServer Info:")
    print(Fore.WHITE + str(server.info))


# Attempt Root DSE information retrieval
def retrieve_root_dse_info(connection):
    print(Fore.CYAN + "\n[" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] Checking Root DSE information...")
    try:
        connection.search(search_base='', search_filter='(objectClass=*)', search_scope=SUBTREE, attributes='*')
        if connection.entries:
            print(Fore.GREEN + "[" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] Root DSE information retrieved:")
            for entry in connection.entries:
                print(Fore.WHITE + str(entry))
        else:
            print(Fore.RED + "[" + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + "] Failed to retrieve Root DSE information.")
    except Exception as e:
        print(Fore.RED + f"[" + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S") + f"] Error retrieving Root DSE information: {e}")


# Enumerate naming contexts
def enumerate_naming_contexts(connection, server):
    print(Fore.CYAN + "\n[" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] Enumerating naming contexts...")
    try:
        for context in server.info.naming_contexts:
            print(Fore.YELLOW + f"\nNaming Context: {context}")
            connection.search(search_base=context, search_filter='(objectClass=*)', search_scope=SUBTREE,
                              attributes='*')
            if connection.entries:
                print(
                    Fore.GREEN + f"[" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + f"] Entries found in {context}:")
                for entry in connection.entries:
                    print(Fore.WHITE + str(entry))
            else:
                print(Fore.RED + f"[" + datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S") + f"] No entries found or access is restricted in {context}.")
    except Exception as e:
        print(Fore.RED + f"[" + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S") + f"] Error enumerating naming contexts: {e}")


# Enumerate schema information
def enumerate_schema(server):
    print(Fore.CYAN + "\n[" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] Enumerating schema...")
    try:
        schema = server.schema
        if schema:
            print(Fore.GREEN + f"[" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + f"] Schema retrieved:")
            print(Fore.YELLOW + f"Attributes: {len(schema.attribute_types)}")
            print(Fore.YELLOW + f"Object Classes: {len(schema.object_classes)}")
            print(Fore.YELLOW + f"Matching Rules: {len(schema.matching_rules)}")
        else:
            print(Fore.RED + "[" + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + "] Schema information could not be retrieved.")
    except Exception as e:
        print(Fore.RED + f"[" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + f"] Error retrieving schema: {e}")


# Enumerate supported controls, extensions, and SASL mechanisms
def enumerate_supported_features(server):
    print(Fore.CYAN + "\n[" + datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S") + "] Enumerating supported controls, extensions, and SASL mechanisms...")

    if server.info.supported_controls:
        print(Fore.GREEN + "\nSupported Controls:")
        for control in server.info.supported_controls:
            print(Fore.WHITE + str(control))

    if server.info.supported_extensions:
        print(Fore.GREEN + "\nSupported Extensions:")
        for ext in server.info.supported_extensions:
            print(Fore.WHITE + str(ext))

    if server.info.supported_sasl_mechanisms:
        print(Fore.GREEN + "\nSupported SASL Mechanisms:")
        for mech in server.info.supported_sasl_mechanisms:
            print(Fore.WHITE + mech)


# Enumerate default users and groups
def enumerate_default_entries(connection, search_base):
    default_entries = [
        ('Admin Users', '(cn=Administrator)'),
        ('Guest Users', '(cn=Guest)'),
        ('Domain Admins', '(cn=Domain Admins)'),
        ('Enterprise Admins', '(cn=Enterprise Admins)'),
        ('Schema Admins', '(cn=Schema Admins)')
    ]

    print(Fore.CYAN + "\n[" + datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S") + "] Attempting to enumerate default entries (users and groups)...")
    for name, filter in default_entries:
        print(Fore.CYAN + f"\nSearching for {name}...")
        connection.search(search_base=search_base, search_filter=filter, search_scope=SUBTREE, attributes='*')
        if connection.entries:
            print(Fore.GREEN + f"[" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + f"] {name} found:")
            for entry in connection.entries:
                print(Fore.WHITE + str(entry))
        else:
            print(Fore.RED + f"[" + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + f"] {name} not found or access is restricted.")


# Suggest potential attack vectors
def suggest_attack_vectors(server):
    print(Fore.CYAN + "\n[" + datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S") + "] Suggested attack vectors and further enumeration methods:")

    # Example suggestions
    if server.info.supported_sasl_mechanisms:
        print(Fore.YELLOW + "1. SASL Mechanisms:")
        print(Fore.WHITE + "   - Check for possible attacks using SASL mechanisms like DIGEST-MD5 or GSSAPI.")

    print(Fore.YELLOW + "2. Schema Enumeration:")
    print(
        Fore.WHITE + "   - Exploit detailed schema information to find potential security misconfigurations or weak attributes.")

    print(Fore.YELLOW + "3. Default Users and Groups:")
    print(
        Fore.WHITE + "   - Enumerate common LDAP groups and users for potential default credentials or privilege escalation.")

    print(Fore.YELLOW + "4. LDAP Injection:")
    print(Fore.WHITE + "   - Test for LDAP injection vulnerabilities by manipulating search filters and attributes.")


# Display options and handle user input
def display_options():
    print(Fore.CYAN + "\nSelect an option for LDAP Enumeration:")
    print(Fore.YELLOW + "1. Enumerate by IP")
    print(Fore.YELLOW + "2. Enumerate with Info")
    print(Fore.YELLOW + "3. Enumerate with Passwords")
    choice = input(Fore.CYAN + "Enter your choice (1/2/3): ")

    if choice == '1':
        server_ip = input(Fore.CYAN + "Enter the LDAP server IP address: ")
        ldap_port = int(input(Fore.CYAN + "Enter the LDAP server port (default is 389): ") or 389)
        connection, server = initialize_connection(server_ip, ldap_port)
        if connection.bind():
            print(Fore.GREEN + "[" + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + "] Successfully connected to the LDAP server!")
            enumerate_naming_contexts(connection, server)
        else:
            print(Fore.RED + "[" + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + "] Failed to connect to the LDAP server.")

    elif choice == '2':
        server_ip = input(Fore.CYAN + "Enter the LDAP server IP address: ")
        ldap_port = int(input(Fore.CYAN + "Enter the LDAP server port (default is 389): ") or 389)
        connection, server = initialize_connection(server_ip, ldap_port)
        if connection.bind():
            print(Fore.GREEN + "[" + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + "] Successfully connected to the LDAP server!")
            print_server_info(server)
            retrieve_root_dse_info(connection)
            enumerate_schema(server)
            enumerate_supported_features(server)
            enumerate_default_entries(connection, 'DC=axlle,DC=htb')
            suggest_attack_vectors(server)
        else:
            print(Fore.RED + "[" + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + "] Failed to connect to the LDAP server.")

    elif choice == '3':
        server_ip = input(Fore.CYAN + "Enter the LDAP server IP address: ")
        ldap_port = int(input(Fore.CYAN + "Enter the LDAP server port (default is 389): ") or 389)
        username = input(Fore.CYAN + "Enter the LDAP server username (if any): ")
        password = input(Fore.CYAN + "Enter the LDAP server password (if any): ")
        connection, server = initialize_connection(server_ip, ldap_port, username, password)
        if connection.bind():
            print(Fore.GREEN + "[" + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + "] Successfully connected to the LDAP server!")
            enumerate_default_entries(connection, 'DC=axlle,DC=htb')
            # Additional password-based enumeration could be implemented here
        else:
            print(Fore.RED + "[" + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + "] Failed to connect to the LDAP server.")

    else:
        print(Fore.RED + "Invalid choice. Please select 1, 2, or 3.")


def main():
    print_banner()
    display_options()


if __name__ == "__main__":
    main()
