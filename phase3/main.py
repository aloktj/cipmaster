import click
import sys
import time
from scapy import all as scapy_all
import os
import math
import threading
import pyfiglet
import string
from termcolor import colored
from tabulate import tabulate
import logging
from datetime import datetime
from struct import pack, unpack
import binascii
import struct

from cip import config as cip_config
from cip import network as cip_network
from cip import session as cip_session


# Create log directory if it doesn't exist
log_dir = "./log"
os.makedirs(log_dir, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='./log/app.log'
)

ENABLE_NETWORK = True
DEBUG_CIP_FRAMES=bool(False)

class CLI:
    lock = threading.Lock()
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.ip_address = None
        self.cip_xml_path = None
        self.net_test_flag = False
        # self.TO_packet = self.AS_VAC_MPU_DATA()
        # self.OT_packet = self.AS_MPU_VAC_DATA()
        self.TO_packet = scapy_all.packet
        self.OT_packet = scapy_all.packet
        self.root = None
        self.config_file_names = []
        self.cip_config_attempts = 0
        self.cip_config_selected = None
        self.overall_cip_valid = False
        self.cip_file_count = 0
        self.last_cip_file_name = None
        self.stop_event = None
        self.stop_events = {}
        self.thread_dict = {}  # Dictionary to store wave threads
        self.cip_test_flag = True
        self.logger.info("Initializing LoggedClass")
        self.can_read_xml_flag = False
        self.platform_multicast_route = None
        self.multicast_route_exist = False
        self.multicast_test_status = False
        self.user_multicast_address = None
        self.time_zone = self.get_system_timezone()
        self.MPU_CTCMSAlive = int(0)
        
        self.bCIPErrorOccured = bool(False)
        self.TO_packet_class = None
        self.OT_packet_class = None
        self.xml = None
        self.ot_eo_assemblies = None
        self.to_assemblies = None
        self.session = cip_session.CIPSession(lock=self.lock, debug_cip_frames=DEBUG_CIP_FRAMES)
        
        
        
        
    ###-------------------------------------------------------------###
    ###                     Header                                  ###
    ###-------------------------------------------------------------###
    
    def spinning_cursor(self):
        while True:
            for cursor in '|/-\\':
                yield cursor
    
    def loading_message(self, message, duration):
        spinner = self.spinning_cursor()
        sys.stdout.write(message)
        sys.stdout.flush()
        start_time = time.time()
        while time.time() - start_time < duration:
            sys.stdout.write(next(spinner))
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b')
        sys.stdout.write('\r')  # Move cursor to the beginning of the line
        sys.stdout.write(' ' * len(message))  # Clear the loading message
        sys.stdout.write('\r')  # Move cursor to the beginning of the line
        sys.stdout.flush()
        
    def progress_bar(self, message, duration):
        click.echo("\n")
        total_ticks = 75  # Number of ticks in the progress bar
        start_time = time.time()
        while time.time() - start_time < duration:
            elapsed_time = time.time() - start_time
            progress = min(int((elapsed_time / duration) * total_ticks), total_ticks)
            remaining = total_ticks - progress
            bar = '[' + '=' * progress + ' ' * remaining + ']'
            sys.stdout.write('\r')
            sys.stdout.write(f'{message} {bar} {elapsed_time:.1f}s/{duration:.1f}s')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\n')
        click.echo("\n")
    
    
    def display_banner(self):
        table_width = 75
        
        click.echo("\n\n")
        banner_text = pyfiglet.figlet_format("\t\t\t\t\t CIP Tool \t\t\t\t\t", font="slant")
        colored_banner = colored(banner_text, color="green")
        
        banner_table = [[colored_banner]]
        click.echo(tabulate(banner_table, tablefmt="plain"))
        
        # Additional information
        print(*"=" * 100, sep="")
        print(("Welcome to CIP Tool").center(table_width))
        print(("Version: 3.0").center(table_width))
        print(("Author: Alok T J").center(table_width))
        print(("Copyright (c) 2024 Wabtec (based on plc.py)").center(table_width))
        print(*"=" * 100, sep="")
    
    ###-------------------------------------------------------------###
    ###                     Multicast Route                         ###
    ###-------------------------------------------------------------###
    
    ###-------------------------------------------------------------###
    ###                     Configuration                           ###
    ###-------------------------------------------------------------###
    
    
    
    def list_files_in_config_folder(self):
        config_folder = "./conf/"
        if not os.path.exists(config_folder) or not os.path.isdir(config_folder):
            click.echo("Config folder does not exist or is not a directory!")
            return
        
        self.config_file_names = os.listdir(config_folder)
        if not self.config_file_names:
            click.echo("No files found in the config folder")
            return
        
        click.echo("Detected Files in Config Folder:")
        click.echo("")
        
        for idx, file in enumerate(self.config_file_names, start=1):
            click.echo(f" {idx}. {file}")
            self.last_cip_file_name = file
            self.cip_file_count += 1
        
        click.echo("")
    
    def cip_config(self):
        self.logger.info("Executing cip_config function")

        click.echo("╔══════════════════════════════════════════╗")
        click.echo("║          CIP Configuration               ║")
        click.echo("╚══════════════════════════════════════════╝")
        self.cip_file_count = 0
        self.config_file_names = []
        self.last_cip_file_name = None
        self.list_files_in_config_folder()
        time.sleep(0.1)

        if self.cip_file_count > 1:
            if self.cip_config_attempts == 0:
                self.cip_config_selected = click.prompt("CIP Configuration Filename")
                click.echo("")
            elif self.cip_config_attempts > 0 and click.confirm('Do you want to change CIP Configuration?', default=True):
                self.cip_config_selected = click.prompt("CIP Configuration Filename")
        else:
            self.cip_config_selected = self.last_cip_file_name

        self.cip_config_attempts += 1

        if not self.cip_config_selected:
            click.echo("No CIP configuration file available.")
            self.overall_cip_valid = False
            self.cip_test_flag = False
            return False

        xml_filepath = os.path.join("./conf", self.cip_config_selected)
        validation = cip_config.validate_cip_config(xml_filepath)

        self.overall_cip_valid = validation.overall_status
        self.cip_test_flag = validation.overall_status
        self.root = validation.root
        self.ot_eo_assemblies = validation.ot_info.assembly if validation.ot_info else None
        self.to_assemblies = validation.to_info.assembly if validation.to_info else None

        if validation.ot_info and validation.ot_info.packet_class is not None:
            self.OT_packet_class = validation.ot_info.packet_class
            self.OT_packet = self.OT_packet_class()
            expected = validation.ot_info.assembly_size // 8
            click.echo(f"Length of OT Assembly Expected: {expected}")
            click.echo(f"Length of OT Assembly Formed: {len(self.OT_packet)}")
        else:
            self.OT_packet_class = None

        if validation.to_info and validation.to_info.packet_class is not None:
            self.TO_packet_class = validation.to_info.packet_class
            self.TO_packet = self.TO_packet_class()
            expected = validation.to_info.assembly_size // 8
            click.echo(f"Length of TO Assembly Expected: {expected}")
            click.echo(f"Length of TO Assembly Formed: {len(self.TO_packet)}")
        else:
            self.TO_packet_class = None

        table = tabulate(validation.results, headers=["Test Case", "Status"], tablefmt="fancy_grid")
        click.echo(table)
        click.echo("")

        if not validation.overall_status:
            click.echo("Some tests failed. Restarting CIP Tool.")

        return validation.overall_status

    def config_network(self):
        self.logger.info("Executing config_network function")
        click.echo("╔══════════════════════════════════════════╗")
        click.echo("║        Network Configuration             ║")
        click.echo("╚══════════════════════════════════════════╝")
        click.echo("")

        self.net_test_flag = False
        self.multicast_test_status = False
        self.multicast_route_exist = False
        self.platform_multicast_route = None

        time.sleep(0.1)

        self.ip_address = click.prompt("Enter Target IP Address", default='10.0.1.1')
        self.user_multicast_address = click.prompt(
            "Enter the multicast group joining IP address",
            default='239.192.1.3',
            type=str,
        )

        click.echo("\n===== Testing Communication with Target =====")
        time.sleep(1)

        network_result = cip_network.config_network(self.ip_address, self.user_multicast_address)

        self.net_test_flag = network_result.reachable
        self.multicast_test_status = network_result.multicast_supported
        self.multicast_route_exist = network_result.route_exists
        self.platform_multicast_route = network_result.route

        results = [
            ["Communication Test Result", "Status"],
            ["Communication with Target", "OK" if network_result.reachable else "FAILED"],
            ["Mutlicast Group Join", "OK" if network_result.multicast_supported else "FAILED"],
            ["Mutlicast route Compatibity", "OK" if network_result.route_exists else "FAILED"],
        ]

        click.echo("\n" + tabulate(results, headers="firstrow", tablefmt="fancy_grid"))
        click.echo("")

        if network_result.reachable and network_result.multicast_supported:
            time.sleep(0.1)
            return True

        click.echo("===== Failed Network Configuration Test =====")
        click.echo("")
        click.echo("=============================================")
        click.echo("=====        Restarting CIP Tool        =====")
        click.echo("=============================================")
        return False

                
    def help_menu(self):
        self.logger.info("Executing help_menu function")
        click.echo("\nAvailable commands:")
        
        commands = [
            ("start", "Stop Communication"),
            ("stop", "Stop Communication"),
            ("set <name> <val>", "Set a field value"),
            ("clear <name>", "Clear a field value"),
            ("get <name>", "Get the current value of a field"),
            ("frame", "Print the packet header and payload"),
            ("fields", "Display the field names"),
            ("wave <name> <max_val> <min_val> <period(ms)>", "Wave a field value"),
            ("stop_wave <name>", "Stop waving for a field value"),
            ("tria <name> <max_val> <min_val> <period(ms)>", "Wave a field value with a triangular waveform"),
            ("box <name> <max_val> <min_val> <period(ms)> <duty_cycle>", "Wave a field value with a square/rectangular waveform"),
            ("live <refresh_rate(ms)>", "Display real-time field data of the specified packet class"),
            ("cip_config", "Restart CIP Config"),
            ("test_net", "Test Network Config"),
            ("log", "Print the recent 100 log events"),
            ("exit", "Exit the application"),
            ("help", "Display this help menu")
        ]

        # commands = [
        #     ("set <name> <val>", "Set a field value"),
        #     ("clear <name>", "Clear a field value"),
        #     ("get <name>", "Get the current value of a field"),
        #     ("frame", "Print the packet header and payload"),
        #     ("fields", "Display the field names"),
        #     ("wave <name> <max_val> <min_val> <period(ms)>", "Wave a field value"),
        #     ("stop_wave <name>", "Stop waving for a field value"),
        #     ("tria <name> <max_val> <min_val> <period(ms)>", "Wave a field value with a triangular waveform"),
        #     ("box <name> <max_val> <min_val> <period(ms)> <duty_cycle>", "Wave a field value with a square/rectangular waveform"),
        #     ("live <refresh_rate(ms)>", "Display real-time field data of the specified packet class"),
        #     ("gui", "Open GUI to display real-time field data"),
        #     ("cip_config", "Restart CIP Config"),
        #     ("test_net", "Test Network Config"),
        #     ("log", "Print the recent 100 log events"),
        #     ("exit", "Exit the application"),
        #     ("help", "Display this help menu")
        # ]
        
        headers = ["Command Usage", "Command Description"]
        table = tabulate(commands, headers=headers, tablefmt="fancy_grid", colalign=("left", "left"))
        click.echo(table)
    



    ###-------------------------------------------------------------###
    ###                     Modification                            ###
    ###-------------------------------------------------------------###
    
    def MPU_heartbeat(self, field_name,field_value):
        self.logger.info("MPU_HeartBeat function executing")
        self.logger.info(f"field name:{field_name}")
        self.logger.info(f"field value:{field_value}")
        
        if hasattr(self.OT_packet,field_name):
            field = getattr(self.OT_packet.__class__, field_name)
            if isinstance(field, scapy_all.ByteField):
                    setattr(self.OT_packet, field_name, field_value)
                    self.logger.info("MPU_HeartBeat set")
            else:
                self.logger.warning("Heartbeat is not ByteField type")
        else:
            self.logger.warning(f"There is no HearBeat with the name: {field_name}")
            
    # def DateTimeSec(self, field_name):
    #     self.logger.info("DateTimeSec function executing")
    #     self.logger.info(f"field name:{field_name}")
    #     timestamp = calendar.timegm(time.gmtime())
    #     try:
    #         if hasattr(self.OT_packet,field_name):
    #             field = getattr(self.OT_packet.__class__, field_name)
    #             if isinstance(field, scapy_all.IEEEDoubleField):
    #                     setattr(self.OT_packet, field_name, timestamp)
    #                     self.logger.info("DateTimeSec set")
    #             else:
    #                 self.logger.warning("DateTimeSec is not IEEEDoubleField type")
    #         else:
    #             self.logger.warning(f"There is no DateTimeSec with the name: {field_name}")
    #     except Exception as err:
    #         self.logger.warning(f" DateTimeSec update for {field_name} FAILED: {err} ")    
    # def DateTimeSec(self, field_name):      
    #     timestamp = calendar.timegm(time.gmtime())
                
    #     if hasattr(self.OT_packet,field_name):
    #         field = getattr(self.OT_packet.__class__, field_name)
    #         if isinstance(field, scapy_all.IEEEDoubleField):
    #                 setattr(self.OT_packet, field_name, timestamp)
    #                 self.logger.info("DateTimeSec is updated")
    #         else:
    #             self.logger.warning("DateTimeSec is not IEEEDoubleField/UDINT type")
    #     else:
    #         self.logger.warning(f"There is no DateTimeSec with the name: {field_name}")
                    
    
    
    def set_field(self, field_name, field_value):
        self.logger.info("Executing set_field function")
        self.stop_wave(field_name)
        self.lock.acquire()
        if hasattr(self.OT_packet, field_name):
            field = getattr(self.OT_packet.__class__, field_name)
            if isinstance(field, scapy_all.IEEEFloatField):
                try:
                    byte_array = struct.pack('f', float(field_value))
                    reversed_byte_array = byte_array[::-1]
                    bE_field_value = struct.unpack('f', reversed_byte_array)[0] #Big endian field value
                    setattr(self.OT_packet, field_name, bE_field_value)
                    print(f"Set {field_name} to {field_value}")
                except ValueError:
                    print(f"Field {field_name} expects a float value.")
            elif isinstance(field, scapy_all.BitField):
                if field_value in ['0', '1']:
                    setattr(self.OT_packet, field_name, int(field_value))
                    print(f"Set {field_name} to {field_value}")
                else:
                    print(f"Field {field_name} expects a value of either '0' or '1'.")
            elif isinstance(field, scapy_all.ByteField):
                if field_value.startswith('0x') and len(field_value) == 4 and all(
                        c in string.hexdigits for c in field_value[2:]):
                    int_value = int(field_value, 16)
                    setattr(self.OT_packet, field_name, int_value)
                    print(f"Set {field_name} to {field_value}")
                elif field_value.isdigit():
                    int_value = int(field_value)
                    if 0 <= int_value <= 0xFF:
                        setattr(self.OT_packet, field_name, int_value)
                        print(f"Set {field_name} to {field_value}")
                    else:
                        print(f"Field {field_name} expects an integer value between 0 and 255.")
                else:
                    print(
                        f"Field {field_name} expects an integer value or a hexadecimal value in the format '0x00' to '0xFF'.")
            
            elif isinstance(field, scapy_all.ShortField):
                if field_value.startswith('0x') and len(field_value) == 6 and all(
                    c in string.hexdigits for c in field_value[2:]):
                    int_value = int(field_value, 16)
                    setattr(self.OT_packet, field_name, int(int_value.to_bytes(2, byteorder='big')))
                    print(f"Set {field_name} to {field_value}")
                elif field_value.isdigit():
                    int_value = int(field_value)
                    if 0 <= int_value <= 0xFFFF:
                        try:
                            byte_array = int_value.to_bytes(2, byteorder='big')
                            reversed_byte_array = byte_array[::-1]
                            converted_value = int.from_bytes(reversed_byte_array, byteorder='big')
                            setattr(self.OT_packet, field_name, converted_value)
                        except:
                            print("Error in setting ShortField")
                        print(f"Set {field_name} to {field_value}")
                    else:
                        print(f"Field {field_name} expects an integer value between 0 and 65535.")
                else:
                    print(f"Field {field_name} expects an integer value or a hexadecimal value in the format '0x0000' to '0xFFFF'.")
            
            ###
            elif isinstance(field, scapy_all.LEShortField):

                if field_value.startswith('0x') and len(field_value) == 4 and all(
                    c in string.hexdigits for c in field_value[2:]):

                    int_value = int(field_value, 16)
                    setattr(self.OT_packet, field_name, int_value.to_bytes(2, byteorder='big'))
                    print(f"Set {field_name} to {field_value}")

                elif field_value.isdigit():

                    int_value = int(field_value)
                    if 0 <= int_value <= 0xFFFF:
                        setattr(self.OT_packet, field_name, int_value) 
                        print(f"Set {field_name} to {field_value}")

                    else:
                        print(f"Field {field_name} expects an integer value between 0 and 65535.")

                else:

                    print(f"Field {field_name} expects an integer value or a hexadecimal value in the format '0x0000' to '0xFFFF'.")
                            
            ###
            
            elif isinstance(field, scapy_all.IEEEDoubleField):

                if field_value.startswith('0x'):

                    int_value = int(field_value, 16)

                    if 0 <= int_value <= (2**64 - 1):  

                        setattr(self.OT_packet, field_name, int_value)

                        print(f"Set {field_name} to {field_value}")

                    else:

                        print("Value out of range for IEEEDoubleField")

                elif field_value.isdigit():

                    int_value = float(field_value)

                    if 0 <= int_value <= (2**64 - 1):

                        setattr(self.OT_packet, field_name, int_value)  

                        print(f"Set {field_name} to {field_value}")

                    else:

                        print("Value out of range for IEEEDoubleField")

                else:

                    print("Field value must be a number for IEEEDoubleField")
            
            
            elif isinstance(field, scapy_all.StrFixedLenField):
                if isinstance(field_value, str):
                    
                    field_value1 = field_value
                    field_value = field_value.encode() # Convert String to Bytes
                    print(field_value)
                if not isinstance(field_value, bytes):
                    print(f"Field values is not byte type")
                field_value1 = field_value
                # field_bytes = field_value.rjust(field.length_from(self.OT_packet), b'\x00')
                                
                if len(field_value) <= field.length_from(self.OT_packet):
                    setattr(self.OT_packet, field_name, field_value)
                    print(f"Set {field_name} to {field_value}")
                else:
                    print(f"Field {field_name} expects a string of length up to {field.length_from(self.OT_packet)}.")
            else:
                print(f"Field {field_name} is not of type IEEEFloatField, BitField, ByteField, or StrFixedLenField and "
                      f"cannot be set.")
        else:
            print(f"Field {field_name} not found.")
            
        self.lock.release()
        
       
    def clear_field(self, field_name):
        self.logger.info("Executing clear_field function")
        self.stop_wave(field_name)
        if hasattr(self.OT_packet, field_name):
            field = getattr(self.OT_packet.__class__, field_name)
            if isinstance(field, scapy_all.IEEEFloatField) or isinstance(field, scapy_all.BitField) or isinstance(field, scapy_all.ByteField):
                setattr(self.OT_packet, field_name, 0)
                print(f"Cleared {field_name}")
            elif isinstance(field, scapy_all.StrFixedLenField):
                setattr(self.OT_packet, field_name, '')
                print(f"Cleared {field_name}")
            else:
                print(f"Cannot clear field {field_name}: unsupported field type.")
        else:
            print(f"Field {field_name} not found.")
            
    def get_field(self, field_name):
        self.logger.info("Executing get_field function")
        timestamp = self.get_timestamp()
        click.echo("")
        click.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
        
        if hasattr(self.OT_packet, field_name):
            field_value = self.get_big_endian_value(self.OT_packet, field_name)
            packet_type = self.OT_packet.__class__.__name__
            field_data = [(packet_type, field_name, self.decrease_font_size(str(field_value)))]
            
            # click.echo(f"{field_name}: {field_value}")
        elif hasattr(self.TO_packet, field_name):
            field_value = self.get_big_endian_value(self.TO_packet, field_name)
            packet_type = self.TO_packet.__class__.__name__
            field_data = [(packet_type, field_name, self.decrease_font_size(str(field_value)))]
            
            # click.echo(f"{field_name}: {field_value}")
        else:
            packet_type = "N/A"
            field_data = [(packet_type, field_name, "Field not found")]
            # click.echo(f"Field {field_name} not found.")
        
        #click.echo(f"\t\t\t {packet_type} \t\t\t")
        click.echo(tabulate(field_data, headers=["CIP-MSG Identifier", "Field Name", "Field Value"], tablefmt="fancy_grid"))
        click.echo("")
          
    def get_big_endian_value(self, packet, field_name):
        field = getattr(packet.__class__, field_name)
        field_value = getattr(packet, field_name)

        if isinstance(field, scapy_all.IEEEFloatField):
            byte_array = struct.pack('f', float(field_value))
            reversed_byte_array = byte_array[::-1]
            bE_field_value = struct.unpack('f', reversed_byte_array)[0]  # Big endian field value
            return bE_field_value

        elif isinstance(field, scapy_all.ShortField):
            byte_array = int(field_value).to_bytes(2, byteorder='big')
            reversed_byte_array = byte_array[::-1]
            bE_field_value = int.from_bytes(reversed_byte_array, byteorder='big')
            return bE_field_value

        elif isinstance(field, scapy_all.ByteField):
            byte_array = int(field_value).to_bytes(1, byteorder='big')
            reversed_byte_array = byte_array[::-1]
            bE_field_value = int.from_bytes(reversed_byte_array, byteorder='big')
            return bE_field_value

        elif isinstance(field, scapy_all.IntField):
            byte_array = int(field_value).to_bytes(4, byteorder='big')
            reversed_byte_array = byte_array[::-1]
            bE_field_value = int.from_bytes(reversed_byte_array, byteorder='big')
            return bE_field_value

        elif isinstance(field, scapy_all.LongField):
            byte_array = int(field_value).to_bytes(8, byteorder='big')
            reversed_byte_array = byte_array[::-1]
            bE_field_value = int.from_bytes(reversed_byte_array, byteorder='big')
            return bE_field_value

        elif isinstance(field, scapy_all.StrField):
            return field_value

        else:
            return field_value
    
    def print_frame(self):
        # Print timestamp
        print(*"=" * 50, sep="")
        click.echo("")
        timestamp = self.get_timestamp()
        click.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
        self.lock.acquire()
        class_name_OT = self.OT_packet.__class__.__name__
        field_data_OT = [(field.name, self.decrease_font_size(str(self.get_big_endian_value(self.OT_packet, field.name)))) for field in self.OT_packet.fields_desc]
        self.lock.release()
        click.echo(f"\t\t\t {class_name_OT} \t\t\t")
        click.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
        click.echo("")
        
        self.lock.acquire()
        class_name_TO = self.TO_packet.__class__.__name__
        field_data_TO = [(field.name, self.decrease_font_size(str(self.get_big_endian_value(self.TO_packet, field.name)))) for field in self.TO_packet.fields_desc]
        self.lock.release()
        click.echo(f"\t\t\t {class_name_TO} \t\t\t")
        click.echo(tabulate(field_data_TO, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
        click.echo("")
        print(*"=" * 50, sep="")
        
    # def print_frame(self):
    #     # Print timestamp
    #     print(*"=" * 50, sep="")
    #     click.echo("")
    #     timestamp = self.get_timestamp()
    #     click.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
        
    #     # Print fields for OT_packet
    #     class_name_OT = self.OT_packet.__class__.__name__
    #     field_data_OT = []
    #     for field in self.OT_packet.fields_desc:
    #         field_name = field.name
    #         field_value = self.decrease_font_size(str(getattr(self.OT_packet, field.name)))
    #         signal_info = self.OT_packet.signal_info.get(field_name, {})
    #         data_type = signal_info.get('type', '')
    #         offset = signal_info.get('offset', '')
    #         length = signal_info.get('length', '')
    #         field_data_OT.append([field_name, field_value, data_type, offset, length])
        
    #     click.echo(f"\t\t\t {class_name_OT} \t\t\t")
    #     click.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value", "Data Type", "Offset", "Length"], tablefmt="fancy_grid"))
    #     click.echo("")
        
    #     # Print fields for TO_packet
    #     class_name_TO = self.TO_packet.__class__.__name__
    #     field_data_TO = []
    #     for field in self.TO_packet.fields_desc:
    #         field_name = field.name
    #         field_value = self.decrease_font_size(str(getattr(self.TO_packet, field.name)))
    #         signal_info = self.TO_packet.signal_info.get(field_name, {})
    #         data_type = signal_info.get('type', '')
    #         offset = signal_info.get('offset', '')
    #         length = signal_info.get('length', '')
    #         field_data_TO.append([field_name, field_value, data_type, offset, length])
        
    #     click.echo(f"\t\t\t {class_name_TO} \t\t\t")
    #     click.echo(tabulate(field_data_TO, headers=["Field Name", "Field Value", "Data Type", "Offset", "Length"], tablefmt="fancy_grid"))
    #     click.echo("")
    #     print(*"=" * 50, sep="")
    
    
    def print_packet_fields(self, title, packet, show_spares=False):
        # Organizing fields by type for the given packet
        fields_by_type = {}
        for field in packet.fields_desc:
            field_type = type(field).__name__
            if field_type not in fields_by_type:
                fields_by_type[field_type] = []
            fields_by_type[field_type].append(field.name)

        packet_table = []
        for field_type, field_names in fields_by_type.items():
            field_str = ", ".join(field_names)
            if len(field_str) > 100:
                # Split field names into chunks without cutting them
                field_str = ""
                curr_len = 0
                for name in field_names:
                    if curr_len + len(name) + 2 > 100:  # Check if adding the next field name exceeds 100 characters
                        field_str += "\n" + name + ", "  # Add newline and comma if needed
                        curr_len = len(name) + 2  # Update current length
                    else:
                        field_str += name + ", "  # Add field name and comma
                        curr_len += len(name) + 2  # Update current length
                field_str = field_str.rstrip(", ")  # Remove trailing comma and space

            packet_table.append([field_type, field_str])

        # If show_spares is False, remove spare fields from packet_table
        if not show_spares:
            packet_table = [row for row in packet_table if not row[0].startswith("Spare_")]

        # Calculate the width of the table
        table_width = 100

        # Print the table with a title header centered above the table
        headers = ["Field Type", "Field Names"]
        colalign = ["left", "left"]  # Setting alignment for both columns to left
        title_header = f"{title}:"
        click.echo(title_header.center(table_width))
        click.echo(tabulate(packet_table, headers=headers, colalign=colalign, tablefmt="fancy_grid"))
        click.echo("")
        
    def list_fields(self):
        self.logger.info("Executing list_fields function")
        
        self.print_packet_fields(self.OT_packet.__class__.__name__ , self.OT_packet)
        
        self.print_packet_fields(self.TO_packet.__class__.__name__ , self.TO_packet)
        
    
    def get_system_timezone(self):
        # Get the system's timezone
        timezone = time.tzname[0]  # Get the timezone abbreviation
        return timezone
    
    def get_timestamp(self):
        # Get the current timestamp in the desired format
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S:%f")[:-3]  # Remove microseconds
        location_code = self.time_zone
        return f"{timestamp} {location_code}"
    
    def decrease_font_size(self, text):
        # Add special characters or spaces to decrease font size
        return " " + text
    
    
        
    def live_field_data(self, refresh_ms):
        self.logger.info("Executing live_field_data function")
        refresh_rate = float(refresh_ms)
        click.echo("")
        try:
            while True:
                # Print timestamp
                print(*"=" * 50, sep="")
                click.echo("")
                timestamp = self.get_timestamp()
                click.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
                
                class_name_OT = self.OT_packet.__class__.__name__
                field_data_OT = [(field.name, self.decrease_font_size(str(getattr(self.OT_packet, field.name)))) for field in self.OT_packet.fields_desc]
                click.echo(f"\t\t\t {class_name_OT} \t\t\t")
                click.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
                click.echo("")
                
                class_name_TO = self.TO_packet.__class__.__name__
                field_data_TO = [(field.name, self.decrease_font_size(str(getattr(self.TO_packet, field.name)))) for field in self.TO_packet.fields_desc]
                click.echo(f"\t\t\t {class_name_TO} \t\t\t")
                click.echo(tabulate(field_data_TO, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
                time.sleep(refresh_rate/1000)  # Adjust the delay as needed for real-time display
                click.echo("")
                print(*"=" * 50, sep="")
        except KeyboardInterrupt:
            print("\nExiting live field data display...")
            return
   
    
    ########################################################################
    # Under Test
    ########################################################################
    
    def wave_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing wave_field function")
        self.stop_wave(field_name)
        field = getattr(self.OT_packet.__class__, field_name)
        if isinstance(field, scapy_all.IEEEFloatField):
            max_value = float(max_value)
            min_value = float(min_value)
            period_ms = float(period_ms) / 1000  # Convert milliseconds to seconds
            amplitude = (max_value - min_value) / 2
            offset = (max_value + min_value) / 2

            def wave_thread():
                self.logger.info("Executing wave_thread function")
                start_time = time.time()
                while not self.stop_events[field_name].is_set():
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    wave_value = amplitude * math.sin(2 * math.pi * elapsed_time / period_ms) + offset
                    
                    byte_array = struct.pack('f', float(wave_value))
                    reversed_byte_array = byte_array[::-1]
                    bE_field_value = struct.unpack('f', reversed_byte_array)[0] #Big endian field value
                    setattr(self.OT_packet, field_name, bE_field_value)
                    
                    # print(f"Set {field_name} to {wave_value}")
                    time.sleep(0.01)  # Adjust sleep time as needed

            self.stop_events[field_name] = threading.Event()
            wave_thread_instance = threading.Thread(target=wave_thread)
            wave_thread_instance.start()
            print(f"Waving {field_name} from {min_value} to {max_value} every {period_ms} milliseconds.")
        else:
            print(f"Field {field_name} is not of type IEEEFloatField and cannot be waved.")
            
    def tria_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing tria_field function")
        self.stop_wave(field_name)
        field = getattr(self.OT_packet.__class__, field_name)
        if isinstance(field, scapy_all.IEEEFloatField):
            max_value = float(max_value)
            min_value = float(min_value)
            period_ms = float(period_ms) / 1000  # Convert milliseconds to seconds
            amplitude = (max_value - min_value) / 2
            offset = (max_value + min_value) / 2

            def tria_wave_thread():
                self.logger.info("Executing tria_wave_thread function")
                start_time = time.time()
                while not self.stop_events[field_name].is_set():
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    phase = elapsed_time / period_ms
                    wave_value = (amplitude * (2 * abs(phase - math.floor(phase + 0.5)) - 1)) + offset
                    byte_array = struct.pack('f', float(wave_value))
                    reversed_byte_array = byte_array[::-1]
                    bE_field_value = struct.unpack('f', reversed_byte_array)[0] #Big endian field value
                    setattr(self.OT_packet, field_name, bE_field_value)
                    # print(f"Set {field_name} to {wave_value}")
                    time.sleep(0.01)  # Adjust sleep time as needed

            self.stop_events[field_name] = threading.Event()
            wave_thread_instance = threading.Thread(target=tria_wave_thread)
            wave_thread_instance.start()
            print(f"Triangular waving {field_name} from {min_value} to {max_value} every {period_ms} milliseconds.")
        else:
            print(f"Field {field_name} is not of type IEEEFloatField and cannot be waved.")
            
    
    def box_field(self, field_name, max_value, min_value, period_ms, duty_cycle):
        self.logger.info("Executing box_field function")
        self.stop_wave(field_name)
        field = getattr(self.OT_packet.__class__, field_name)
        if isinstance(field, scapy_all.IEEEFloatField):
            max_value = float(max_value)
            min_value = float(min_value)
            period_ms = float(period_ms) / 1000  # Convert milliseconds to seconds
            duty_cycle = float(duty_cycle)
            # amplitude = (max_value - min_value) / 2
            # offset = (max_value + min_value) / 2

            def box_wave_thread():
                self.logger.info("Executing box_wave_thread function")
                start_time = time.time()
                while not self.stop_events[field_name].is_set():
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    duty_period = period_ms * duty_cycle
                    wave_value = max_value if (elapsed_time % period_ms) < duty_period else min_value
                    byte_array = struct.pack('f', float(wave_value))
                    reversed_byte_array = byte_array[::-1]
                    bE_field_value = struct.unpack('f', reversed_byte_array)[0] #Big endian field value
                    setattr(self.OT_packet, field_name, bE_field_value)
                    # print(f"Set {field_name} to {wave_value}")
                    time.sleep(0.01)  # Adjust sleep time as needed

            self.stop_events[field_name] = threading.Event()
            wave_thread_instance = threading.Thread(target=box_wave_thread)
            wave_thread_instance.start()
            print(f"Generating square wave for {field_name} with duty cycle {duty_cycle} every {period_ms} milliseconds.")
        else:
            print(f"Field {field_name} is not of type IEEEFloatField and cannot be waved.")
            
    def stop_all_thread(self):
        self.logger.info(f"{self.stop_all_thread.__name__}: Stopping all wave threads for domain")
        for field_name in self.stop_events:
            self.stop_events[field_name].set()
            click.echo(f"{self.stop_all_thread.__name__}: Waving for '{field_name}' has been stopped")
        self.logger.info(f"{self.stop_all_thread.__name__}: All wave threads have been successfully stopped")

            
    def stop_wave(self, field_name):
        self.logger.info("Executing stop_wave function")
        if field_name in self.stop_events and not self.stop_events[field_name].is_set():
            self.stop_events[field_name].set()
            click.echo(f"\nWaving for '{field_name}' has been stopped.\n")
            
    def print_last_logs(self):
        log_file_path = "./log/app.log"
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as log_file:
                lines = log_file.readlines()
                last_100_lines = lines[-100:]
                click.echo("Last 100 lines of app.log:")
                for line in last_100_lines:
                    click.echo(line.strip())
    
    def calculate_connection_params(self):
        ot_size = None
        to_size = None

        try:
            ot_size = int(self.ot_eo_assemblies.attrib.get("size"))
            to_size = int(self.to_assemblies.attrib.get("size"))
        except:
            self.logger.info("Unable to fetch assembly size")

        # Calculate OT_Connection_param and TO_Connection_param
        if ot_size is not None:
            ot_connection_param = 0x4800 | ((ot_size // 8) + 6)
        else:
            ot_connection_param = None
        if to_size is not None:
            to_connection_parma = 0x2800 | ((to_size // 8) + 6)
        else:
            to_connection_parma = None

        return (ot_connection_param,to_connection_parma)

    def _update_to_packet(self, packet):
        with self.lock:
            self.TO_packet = packet
    
    def start_comm(self):
        self.logger.info("Executing CIP Communication Start function")

        if self.session.running:
            click.echo("CIP communication is already running.")
            return

        if self.TO_packet_class is None or self.OT_packet_class is None:
            click.echo("CIP packets are not initialised. Run 'cip_config' first.")
            return

        if self.ip_address is None or self.user_multicast_address is None:
            click.echo("Network configuration is incomplete. Run 'test_net' first.")
            return

        ot_param, to_param = self.calculate_connection_params()
        if ot_param is None or to_param is None:
            click.echo("Unable to calculate connection parameters from the assemblies.")
            return

        params = cip_session.ConnectionParameters(ot_param=ot_param, to_param=to_param)

        try:
            self.session.start(
                ip_address=self.ip_address,
                multicast_address=self.user_multicast_address,
                connection_params=params,
                to_packet_class=self.TO_packet_class,
                ot_packet=self.OT_packet,
                heartbeat_callback=self.MPU_heartbeat,
                update_to_packet=self._update_to_packet,
            )
        except RuntimeError as exc:
            click.echo(str(exc))

    def stop_comm(self):
        self.logger.info(f"{self.stop_comm.__name__}: Stopping comm thread")
        if not self.session.running:
            click.echo("No active CIP communication session.")
            return

        self.session.stop()
        self.bCIPErrorOccured = self.session.error_occurred
        click.echo("CIP communication stopped.")


 
    
    def handle_input(self):
        self.logger.info("Executing handle_input function")
        # click.echo("Handle Input is Printed")
        self.help_menu()
        
        try:
            while True:
                    print("")
                    command = click.prompt("Enter Command").strip().split()
                    if command[0] == "start" and len(command) == 1:
                        self.start_comm()
                    elif command[0] == "stop" and len(command) == 1:
                        self.stop_comm()
                    elif command[0] == "set" and len(command) == 3:
                        self.set_field(command[1], command[2])
                    elif command[0] == "clear" and len(command) == 2:
                        self.clear_field(command[1])
                    elif command[0] == "get" and len(command) == 2:
                        self.get_field(command[1])
                    elif command[0] == "frame" and len(command) == 1:
                        self.print_frame()
                    elif command[0] == "fields" and len(command) == 1:
                        self.list_fields()
                    elif command[0] == "wave" and len(command) == 5:
                        self.wave_field(command[1], float(command[2]), float(command[3]), int(command[4]))
                    elif command[0] == "tria" and len(command) == 5:
                        self.tria_field(command[1], float(command[2]), float(command[3]), int(command[4]))
                    elif command[0] == "box" and len(command) == 6:
                        self.box_field(command[1], float(command[2]), float(command[3]), int(command[4]), float(command[5]))
                    elif command[0] == "live" and len(command) == 2:
                        self.live_field_data(command[1])
                    elif command[0] == "stop_wave" and len(command) == 2:
                        # self.stop_wave()
                        self.stop_wave(command[1])
                    elif command[0] == "cip_config" and len(command) == 1:
                        while False == self.cip_config() :
                            self.cip_config()
                    elif command[0] == "test_net" and len(command) == 1:
                        while False == self.config_network() :
                            self.config_network()
                    elif command[0] == "log" and len(command) == 1:
                        self.print_last_logs()
                    elif command[0] == "help":
                        self.help_menu()
                    elif command[0] == "exit":
                        click.echo("Exiting !")
                        self.stop_all_thread()
                        sys.exit()
                    else:
                        click.echo("Invalid cmd")
            
        except KeyboardInterrupt:
            click.echo("Exiting !!")
            self.stop_all_thread()
            sys.exit()
                
            
def main():
    # plc_object = client('127.0.0.1')
    
    global ENABLE_NETWORK
    cmd = CLI()
    cmd.display_banner()
    
    cmd.progress_bar("Initializing", 1)
    
    
    if cmd.cip_test_flag:
        if click.confirm('Do you want to continue?', default=True):
            # If user answers yes
            cmd.cip_config()
        else:
            # If user answers no
            click.echo('Exiting...')
            sys.exit()
        
        
    # Test CIP Configuration
    if not cmd.cip_test_flag:
        main() # Restart configuration if failed

    
    
    # Test Target Communication
    if ENABLE_NETWORK:
        if not cmd.config_network():
            main()  # Restart configuration if failed


            
    # Handle the Input from User in a loop
    cmd.handle_input()

if __name__ == "__main__":
    main()
