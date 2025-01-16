# Agility Palo Alto Session Finder Script

> The script connects to the firewall using the Netmiko library for SSH connection, collects active sessions, performs a new search based on session IDs, identifies which rules have active sessions, and saves the rule names with active sessions in .txt and .csv files.

## 💻 Prerequisites

Before starting, make sure you meet the following requirements:

* Install the netmiko library `<pip install netmiko>`
* Install the pandas library `<pip install pandas>`

## 🚀 Using the Palo Alto Rule With Session Finder <Staging Script>

1. Start the script as desired!
2. When starting, you must provide the IP Address, Username, and Password configured on the firewall.
3. The script will establish an SSH connection to the firewall and retrieve active session data.
4. The script will then analyze the session data to identify which rules have active sessions.
5. The rule names and filter commands are saved in the root directory in .txt and .csv files.

## 📄 Output Files

The script generates the following output files:
* `active_sessions.txt` - Contains the list of rules with active sessions.
* `active_sessions.csv` - Contains the list of rules with active sessions in CSV format.

## 🤝 Criador

To people who contributed and created this project:

<table>
  <tr>
    <td align="center">
      <a href="#">
        <img src="https://avatars.githubusercontent.com/u/144133682" width="100px;" alt="Photo by Fábio Barbosa on GitHub"/><br>
        <sub>
          <b>Fábio Barbosa</b>
        </sub>
      </a>
    </td>
  </tr>
</table>