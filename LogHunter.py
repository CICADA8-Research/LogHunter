# LogHunter.py
#
# Description:
#   Find user session's by parsing event logs
# 
# Author:
#   Michael Zhmaylo (MzHmO)

import logging
import argparse
import sys
import struct
from queue import Queue
from threading import Thread
from datetime import datetime, timezone
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import even, transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


EVENTLOG_SEEK_READ = 0x00000002
EVENTLOG_FORWARDS_READ = 0x00000004
MAX_BATCH_BUFF = 0x7ffff

event_descriptions = {
    4624: "An account was successfully logged on.",
    4768: "A Kerberos authentication ticket (TGT) was requested.",
    4672: "Special privileges assigned to new logon.",
    4769: "A Kerberos service ticket (TGS) was requested."
}

event_4624_fields = [
    "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
    "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId",
    "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName",
    "LogonGuid", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId",
    "ProcessName", "IpAddress", "IpPort", "ImpersonationLevel", "RestrictedAdminMode",
    "TargetOutboundUserName", "TargetOutboundDomainName", "VirtualAccount",
    "TargetLinkedLogonId", "ElevatedToken"
]

event_4672_fields = [
    "SubjectUserSid", "SubjectUserName", "SubjectDomainName","SubjectLogonId", "PrivilegeList"
]

event_4768_fields = [
    "TargetUserName", "TargetDomainName", "TargetSid", "ServiceName",
    "ServiceSid", "TicketOptions", "Status", "TicketEncryptionType",
    "PreAuthType", "IpAddress", "IpPort", "CertIssuerName",
    "CertSerialNumber", "CertThumbprint"
]

event_4769_fiels = [
    "TargetUserName", "TargetDomainName", "ServiceName",
    "ServiceSid", "TicketOptions", "TicketEncryptionType",
    "IpAddress", "IpPort", "Status", "LogonGuid", "TransmittedServices"
]

event_fields_mapping = {
    4624: event_4624_fields,
    4672: event_4672_fields,
    4768: event_4768_fields,
    4769: event_4769_fiels
}

class DebugHelper:
    @staticmethod
    def PrintClassInstanceAttributes(instance):
        attributes = [attribute for attribute in dir(instance) if not attribute.startswith('__')]
        
        for attr in attributes:
            value = getattr(instance, attr)
            logging.debug((f"{attr}: {value}"))

class Parser:
    @staticmethod
    def decode_string(data_bytes, offset):
        end = data_bytes.find(b'\x00\x00\x00', offset)
        decoded_string = data_bytes[offset:end].decode('utf-8')
        return decoded_string, end + 1
    
    @staticmethod
    def handle_padding(offset):
        return offset + (4 - (offset % 4)) % 4

    @staticmethod
    def decode_strings(data_bytes, record):
        strings = []
        offset = record['StringOffset']
        for _ in range(record['NumStrings']):
            end = data_bytes.find(b'\x00\x00\x00', offset)
            if end == -1:
                break

            decoded_string = data_bytes[offset:end].decode('utf-8')
            offset = end + 1
            strings.append(decoded_string)
            
        return strings
    
    @staticmethod
    def extract_username(data_string):
        username = data_string
        username_position = data_string.rfind('\x04\x00')

        if username_position == -1:
            username_position = data_string.rfind('\x04@\x04@')

            if username_position == -1:
                username_position = data_string.rfind('\x04@')

        data_bytes = bytes(data_string, "latin1") 
        
        try:
            if (username_position != -1):
                username = data_bytes[:username_position + 3].decode('utf-16') + "@" + data_bytes[username_position:].decode('utf-8')
        
        except Exception as e:
            logging.debug("Failed to parse username")
        return username

class MsEvenHandler:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__dce = None

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

        
    def bound(self, address):
        stringbinding = r'ncacn_np:%s[\pipe\eventlog]' % address
        # stringbinding = r'82273FDC-E32A-18C3-3F78-827929DC23EA@ncacn_np:%s[\pipe\eventlog]' % address
        logging.debug(rf"Trying to connect on {address}\pipe\eventlog, stringbinding: {stringbinding} on user {self.__username}")
        
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        rpctransport.set_credentials(username=self.__username,
                                     password=self.__password,
                                     domain=self.__domain,
                                     lmhash=self.__lmhash,
                                     nthash=self.__nthash,
                                     aesKey=self.__aesKey,
                                     )
        
        self.__dce = rpctransport.get_dce_rpc()

        if (self.__doKerberos):
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.__dce.connect()

        self.__dce.bind(even.MSRPC_UUID_EVEN)
        logging.debug("Successfully bound to MS-EVEN")
    
        return self.__dce
    
    

    @staticmethod
    def process_logs(q):
        while True:
            try:
                data_bytes = q.get()
                if data_bytes is None:
                    continue
            
                format_string = 'IIIIIIHHHHIIIIII'
                current_offset = struct.calcsize(format_string)
                eventlogrecord = struct.unpack_from(format_string, data_bytes, 0) 

                fields = [
                    'Length', 'Reserved', 'RecordNumber', 'TimeGenerated',
                    'TimeWritten', 'EventID', 'EventType', 'NumStrings',
                    'EventCategory', 'ReservedFlags', 'ClosingRecordNumber',
                    'StringOffset', 'UserSidLength', 'UserSidOffset', 'DataLength', 'DataOffset'
                ]

                record = dict(zip(fields, eventlogrecord))

                if record['EventID'] not in [4624, 4768, 4672, 4769]:
                    continue

                logging.info("------------------")
                logging.info(f"[NEW EVENT FOUND]")
                logging.info(f"EventID: {record['EventID']}")
                record['Description'] = event_descriptions[record['EventID']]
                logging.info(f"Description: {record['Description']}")

                time_generated = datetime.fromtimestamp(record['TimeGenerated'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                
                logging.info(f"Time Generated: {time_generated}")
                

                current_offset = current_offset
                record['SourceName'], current_offset = Parser.decode_string(data_bytes, current_offset)
                sourcename_escaped = record['SourceName'].replace('\x00', '')
                logging.info(f"SourceName: {sourcename_escaped}")


                record['ComputerName'], current_offset = Parser.decode_string(data_bytes, current_offset)
                computername_escaped = record['ComputerName'].replace('\x00', '')
                logging.info(f"ComputerName: {computername_escaped}")
                
                current_offset = Parser.handle_padding(current_offset)
                if record['UserSidLength'] > 0:
                    record['UserSid'] = data_bytes[record['UserSidOffset']:record['UserSidOffset'] + record['UserSidLength']]
                else:
                    record['UserSid'] = None
                logging.info(f"UserSid: {record['UserSid']}")

                record['Strings'] = Parser.decode_strings(data_bytes, record)
                
                string_names = event_fields_mapping[record['EventID']]
                
                i = 0
                j = 0

                while i < len(string_names):
                    if (j > 1 and record['Strings'][j - 1] == record[field_name] and i != j):
                        if (record['EventID'] not in [4768]):
                            j += 1

                    field_name = string_names[i]
                    s = record['Strings'][j]

                    if (field_name in ['SubjectUserName', 'TargetUserName']):
                        record[field_name] = Parser.extract_username(s)
                        i += 1

                    elif (field_name == 'SubjectDomainName'):
                        try:
                            record[field_name] = record['SubjectUserName'].rsplit("@", 1)[1]
                        except:
                            record[field_name] = s
                        
                        i += 1
                        j += 1
                    
                    elif (field_name == 'TargetDomainName'):
                        try:
                            record[field_name] = record['TargetUserName'].rsplit("@", 1)[1]
                        except:
                            record[field_name] = s

                        i += 1
                        j += 1

                    elif (field_name == "ServiceName"):
                        
                        if (record['EventID'] == 4769):
                            if (i != j):
                                i = j
                        
                            s = record['Strings'][j]
                            record[field_name] = s
                            i += 1
                            j += 1

                        if (record['EventID'] == 4768):
                            record[field_name] = "krbtgt"
                            i = max(i, j) + 1
                            j = i - 1
                            

                    else:
                        record[field_name] = s
                        i += 1
                        j += 1
                    
                    field_name_escaped = field_name.replace('\x00', '')
                    record_name_value = record[field_name].replace('\x00', '')
                    logging.info(f"{field_name_escaped}: {record_name_value}")

                if record['DataLength'] > 0:
                    record['Data'] = data_bytes[record['DataOffset']:record['DataOffset'] + record['DataLength']]
                else:
                    record['Data'] = None
                
                length2_format = 'I'
                length2 = struct.unpack_from(length2_format, data_bytes, record['Length'] - struct.calcsize(length2_format))[0]
                record['Length2'] = length2

                logging.info("------------------")
            
            finally:
                q.task_done()

    @staticmethod
    def read_logs(q, dce, hLogHandle, recordscount):
        record_offset = recordscount
        while record_offset > 1:
            response = even.hElfrReadELW(
                dce=dce,
                logHandle=hLogHandle,
                readFlags=EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ,
                recordOffset=record_offset,
                numberOfBytesToRead=MAX_BATCH_BUFF
            )

            data_bytes = b''.join(response['Buffer'])
        
            q.put(data_bytes)

            record_offset -= 1

        q.put(None)


if __name__ == "__main__":
    print("--------------------------------")
    print("[+] LogHunter.py - a tool for finding user sessions by analyzing event log files through RPC (MS-EVEN) [+]")
    print("--------------------------------")
    
    parser = argparse.ArgumentParser(add_help=True, description="Trying to find user session behalf of 4624, 4768, 4769 and 4672 events "
                                                                "using MS-EVEN.")
    
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address. From these computer u will receive the logs>')    
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-outfile', action='store', metavar="output file", help='file with information about sessions', default="events.log")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler(options.outfile),
                            logging.StreamHandler()
                        ])
    else:
        logging.basicConfig(level=logging.INFO, format='%(message)s',
                        handlers=[
                            logging.FileHandler(options.outfile),
                            logging.StreamHandler()
                        ])

    if options.aesKey is not None:
        options.k = True

    domain, username, password, address = parse_target(options.target)
    
    logHunter = MsEvenHandler(username=username, password=password, domain=domain,
                              hashes=options.hashes, aesKey=options.aesKey, doKerberos=options.k, kdcHost=options.dc_ip)
    
    DebugHelper.PrintClassInstanceAttributes(logHunter)

    try:
        recordscount = 0
        oldestrecord = 0

        dce = logHunter.bound(address=address)

        response = even.hElfrOpenELW(dce=dce, moduleName="Security")

        hLogHandle = response['LogHandle']

        response = even.hElfrNumberOfRecords(dce=dce, logHandle=hLogHandle)
        recordscount = response['NumberOfRecords']
        logging.debug(f"Found {recordscount} records")

        log_queue = Queue()
        processing_thread = Thread(target=MsEvenHandler.process_logs, args=(log_queue,))
        reader_thread = Thread(target=MsEvenHandler.read_logs,args=(log_queue, dce, hLogHandle, recordscount))

        processing_thread.start()
        reader_thread.start()
        reader_thread.join()
        processing_thread.join()

    except Exception as e:
        print(f"An error occured: {str(e)}")

    finally:
        even.hElfrCloseEL(dce=dce, logHandle=hLogHandle)