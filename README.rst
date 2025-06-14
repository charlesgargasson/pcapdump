#########
PCAP Dump
#########

| Alternative to pcap2john, using tshark (instead of scapy)

|

***************
Getting started
***************

.. code-block:: bash

    pipx install git+https://github.com/charlesgargasson/pcapdump@main
    # pipx uninstall pcapdump
    # pipx upgrade pcapdump

.. code-block:: bash

    pcapdump -f capture.pcap

|

*********
Supported
*********

| Supported secrets (WIP)

.. code-block:: bash

    # KERBEROS
    ✅ AS-REQ 17/18  # 10 ; 19800/19900 ; sensitive username, insensitive realm
    ✅ AS-REQ 23     # 10 ; 7500 ; optional user/realm
    ✅ AS-REP 23     # 11 ; 18200 ; optional user/realm
    ✅ TGS-REP 17/18 # 13 ; 19600/19700 ; sensitive username, insensitive realm
    ✅ TGS-REP 23    # 13 ; 13100 ; optional user/realm/spn

    # NTLM-SSP Net-NTLM v1/v2
    # pcapdump don't stick to specific protocols but parse wireshark NTLMSSP layer
    ✅ SMB2
    ✅ LDAP
    ✅ DCERPC // RPC // WMI
    ✅ HTTP // WINRM

|

| https://hashcat.net/wiki/doku.php?id=example_hashes

|

************
Troubleshoot
************

| Kerberos etype 17/18 username is case sensitive (eg: "John.DOE")
| If the username value of ticket don't match the real one, hashcat will fail.
| You can check the username using LDAP, or test other formats such as "john.doe" or "JOHN.DOE".

|

**********
Ressources
**********

| https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py
| https://github.com/hashcat/hashcat/blob/master/src/modules/module_19700.c
| https://github.com/odedshimon/BruteShark
| https://www.netresec.com/?page=NetworkMiner

|