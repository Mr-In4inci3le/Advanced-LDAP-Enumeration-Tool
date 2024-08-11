# Advanced LDAP Enumeration Tool

## Description

This tool is designed for advanced LDAP enumeration and attack simulations. It retrieves detailed LDAP server information, including root DSE information, naming contexts, schema details, supported features, and default entries. Additionally, it provides suggestions for potential attack vectors based on the gathered data.

The script supports three main options:
1. **Enum by IP**: Enumerates LDAP server information based on the provided IP address.
2. **Enum with Info**: Retrieves and displays detailed LDAP server information.
3. **Enum with Passwords**: Includes additional enumeration with password-related queries.

## Features

- **Root DSE Information**: Retrieves and displays root DSE details.
- **Naming Contexts**: Enumerates and displays LDAP naming contexts.
- **Schema Enumeration**: Retrieves and displays schema information.
- **Supported Features**: Lists supported LDAP controls, extensions, and SASL mechanisms.
- **Default Entries**: Searches for common LDAP users and groups.
- **Attack Vectors**: Provides suggestions for potential attack vectors and further enumeration.

## Prerequisites

- Python 3.x
- `ldap3` library
- `colorama` library

## License

This project is licensed under the MIT License. See the (LICENSE) file for details.

## Author

- **Invincible**

For any issues or questions, please open an issue on the GitHub repository or contact me via instagram @hack3r_codes directly.

