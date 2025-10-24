import sys
import time
from scapy import all as scapy_all
import os
import math
import threading
import pyfiglet
from termcolor import colored
from tabulate import tabulate
import logging
from datetime import datetime
import binascii
from dataclasses import dataclass
from typing import Any, Optional

from cipmaster.cip import config as cip_config
from cipmaster.cip import fields as cip_fields
from cipmaster.cip import network as cip_network
from cipmaster.cip.ui import ClickUserInterface, UserInterface
from cipmaster.services.config_loader import ConfigLoaderService
from cipmaster.services.networking import NetworkingService
from cipmaster.services.sessions import SessionService


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


@dataclass
class RunConfiguration:
    """Configuration flags for scripted runs of the CLI."""

    auto_continue: Optional[bool] = None
    cip_filename: Optional[str] = None
    target_ip: Optional[str] = None
    multicast_address: Optional[str] = None
    enable_network: Optional[bool] = None


class CIPCLI:
    lock = threading.Lock()

    def __init__(
        self,
        *,
        ui: Optional[UserInterface] = None,
        config_loader: Optional[ConfigLoaderService] = None,
        networking: Optional[NetworkingService] = None,
        sessions: Optional[SessionService] = None,
        network_configurator=None,
    ):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.ui = ui or ClickUserInterface()
        self.config_loader = config_loader or ConfigLoaderService()
        self.networking = networking or NetworkingService()
        self.sessions = sessions or SessionService()
        if network_configurator is None:
            self.network_configurator = self.networking.configure_network
        else:
            self.network_configurator = network_configurator
        self.ip_address = None
        self.cip_xml_path = None
        self.net_test_flag = False
        # self.TO_packet = self.AS_VAC_MPU_DATA()
        # self.OT_packet = self.AS_MPU_VAC_DATA()
        self.TO_packet = scapy_all.Packet()
        self.OT_packet = scapy_all.Packet()
        self.root = None
        self.config_file_names = []
        self.config_file_map = {}
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
        self.session = self.sessions.create_session(lock=self.lock, debug_cip_frames=DEBUG_CIP_FRAMES)




    ###-------------------------------------------------------------###
    ###                     Header                                  ###
    ###-------------------------------------------------------------###

    def prompt(self, text: str, **kwargs):
        return self.ui.prompt(text, **kwargs)

    def confirm(self, text: str, **kwargs) -> bool:
        return self.ui.confirm(text, **kwargs)

    def echo(self, message: str = "", *, nl: bool = True) -> None:
        self.ui.echo(message, nl=nl)

    def write(self, *args, sep: str = " ", end: str = "\n") -> None:
        self.ui.write(*args, sep=sep, end=end)

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
        self.echo("\n")
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
        self.echo("\n")
    
    
    def display_banner(self):
        table_width = 75
        
        self.echo("\n\n")
        banner_text = pyfiglet.figlet_format("\t\t\t\t\t CIP Tool \t\t\t\t\t", font="slant")
        colored_banner = colored(banner_text, color="green")
        
        banner_table = [[colored_banner]]
        self.echo(tabulate(banner_table, tablefmt="plain"))
        
        # Additional information
        self.write(*"=" * 100, sep="")
        self.write(("Welcome to CIP Tool").center(table_width))
        self.write(("Version: 3.0").center(table_width))
        self.write(("Author: Alok T J").center(table_width))
        self.write(("Copyright (c) 2024 Wabtec (based on plc.py)").center(table_width))
        self.write(*"=" * 100, sep="")
    
    ###-------------------------------------------------------------###
    ###                     Multicast Route                         ###
    ###-------------------------------------------------------------###
    
    ###-------------------------------------------------------------###
    ###                     Configuration                           ###
    ###-------------------------------------------------------------###
    
    
    
    def list_files_in_config_folder(self):
        self.config_file_map = self.config_loader.get_available_config_files()
        self.config_file_names = sorted(self.config_file_map)
        if not self.config_file_names:
            self.echo("No CIP configuration files were found. Place XML files in the 'conf'"
                      " directory or install a package that provides them.")
            return

        self.echo("Detected Files in Config Folder:")
        self.echo("")

        for idx, file in enumerate(self.config_file_names, start=1):
            self.echo(f" {idx}. {file}")
            self.last_cip_file_name = file
            self.cip_file_count += 1
        
        self.echo("")
    
    def cip_config(self, preselected_filename: Optional[str] = None):
        self.logger.info("Executing cip_config function")

        self.echo("╔══════════════════════════════════════════╗")
        self.echo("║          CIP Configuration               ║")
        self.echo("╚══════════════════════════════════════════╝")
        self.cip_file_count = 0
        self.config_file_names = []
        self.config_file_map = {}
        self.last_cip_file_name = None
        self.list_files_in_config_folder()
        time.sleep(0.1)

        if preselected_filename is not None and self.cip_config_attempts == 0:
            self.cip_config_selected = preselected_filename
        elif self.cip_file_count > 1:
            if self.cip_config_attempts == 0:
                self.cip_config_selected = self.prompt("CIP Configuration Filename")
                self.echo("")
            elif self.cip_config_attempts > 0 and self.confirm('Do you want to change CIP Configuration?', default=True):
                self.cip_config_selected = self.prompt("CIP Configuration Filename")
        else:
            self.cip_config_selected = self.last_cip_file_name

        self.cip_config_attempts += 1

        if not self.cip_config_selected:
            self.echo("No CIP configuration file available.")
            self.overall_cip_valid = False
            self.cip_test_flag = False
            return False

        try:
            xml_filepath = self.config_loader.resolve_config_path(
                self.cip_config_selected,
                available=self.config_file_map,
            )
        except cip_config.ConfigNotFoundError:
            self.echo(f"CIP configuration '{self.cip_config_selected}' not found.")
            self.overall_cip_valid = False
            self.cip_test_flag = False
            return False

        validation = self.config_loader.validate_cip_config(os.fspath(xml_filepath))

        self.overall_cip_valid = validation.overall_status
        self.cip_test_flag = validation.overall_status
        self.root = validation.root
        self.ot_eo_assemblies = validation.ot_info.assembly if validation.ot_info else None
        self.to_assemblies = validation.to_info.assembly if validation.to_info else None

        if validation.ot_info and validation.ot_info.packet_class is not None:
            self.OT_packet_class = validation.ot_info.packet_class
            self.OT_packet = self.OT_packet_class()
            expected = validation.ot_info.assembly_size // 8
            self.echo(f"Length of OT Assembly Expected: {expected}")
            self.echo(f"Length of OT Assembly Formed: {len(self.OT_packet)}")
        else:
            self.OT_packet_class = None

        if validation.to_info and validation.to_info.packet_class is not None:
            self.TO_packet_class = validation.to_info.packet_class
            self.TO_packet = self.TO_packet_class()
            expected = validation.to_info.assembly_size // 8
            self.echo(f"Length of TO Assembly Expected: {expected}")
            self.echo(f"Length of TO Assembly Formed: {len(self.TO_packet)}")
        else:
            self.TO_packet_class = None

        table = tabulate(validation.results, headers=["Test Case", "Status"], tablefmt="fancy_grid")
        self.echo(table)
        self.echo("")

        if not validation.overall_status:
            self.echo("Some tests failed. Restarting CIP Tool.")

        return validation.overall_status

    def config_network(
        self,
        ip_address: Optional[str] = None,
        multicast_address: Optional[str] = None,
        *,
        ping_command: Optional[cip_network.CommandType] = None,
        platform_service: Optional[cip_network.PlatformService] = None,
        subprocess_service: Optional[cip_network.SubprocessService] = None,
    ):
        self.logger.info("Executing config_network function")
        self.echo("╔══════════════════════════════════════════╗")
        self.echo("║        Network Configuration             ║")
        self.echo("╚══════════════════════════════════════════╝")
        self.echo("")

        self.net_test_flag = False
        self.multicast_test_status = False
        self.multicast_route_exist = False
        self.platform_multicast_route = None

        time.sleep(0.1)

        self.ip_address = (
            ip_address
            if ip_address is not None
            else self.prompt("Enter Target IP Address", default='10.0.1.1')
        )
        self.user_multicast_address = (
            multicast_address
            if multicast_address is not None
            else self.prompt(
                "Enter the multicast group joining IP address",
                default='239.192.1.3',
                type=str,
            )
        )

        self.echo("\n===== Testing Communication with Target =====")
        time.sleep(1)

        network_result = self.network_configurator(
            self.ip_address,
            self.user_multicast_address,
            ping_command=ping_command,
            platform_service=platform_service,
            subprocess_service=subprocess_service,
        )

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

        self.echo("\n" + tabulate(results, headers="firstrow", tablefmt="fancy_grid"))
        self.echo("")

        if network_result.reachable and network_result.multicast_supported:
            time.sleep(0.1)
            return True

        self.echo("===== Failed Network Configuration Test =====")
        self.echo("")
        self.echo("=============================================")
        self.echo("=====        Restarting CIP Tool        =====")
        self.echo("=============================================")
        return False

                
    def help_menu(self):
        self.logger.info("Executing help_menu function")
        self.echo("\nAvailable commands:")
        
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
        self.echo(table)
    



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
        try:
            if not hasattr(self.OT_packet, field_name):
                self.write(f"Field {field_name} not found.")
                return

            field = getattr(self.OT_packet.__class__, field_name)
            metadata = cip_fields.get_field_metadata(self.OT_packet, field_name)
            codec = cip_fields.get_field_codec(field)
            if codec is None:
                validation = cip_fields.describe_validation(field, packet=self.OT_packet, metadata=metadata)
                field_type = validation.get("type", field.__class__.__name__)
                self.write(
                    f"Field {field_name} has unsupported type {field_type} and cannot be set via this command."
                )
                return

            try:
                encoded_value = cip_fields.encode_field_value(
                    field,
                    field_value,
                    field_name=field_name,
                    packet=self.OT_packet,
                    metadata=metadata,
                )
            except ValueError as exc:
                self.write(str(exc))
                return

            setattr(self.OT_packet, field_name, encoded_value)
            self.write(f"Set {field_name} to {field_value}")
        finally:
            self.lock.release()
        
       
    def clear_field(self, field_name):
        self.logger.info("Executing clear_field function")
        self.stop_wave(field_name)
        if hasattr(self.OT_packet, field_name):
            field = getattr(self.OT_packet.__class__, field_name)
            codec = cip_fields.get_field_codec(field)
            if codec is None:
                self.write(f"Cannot clear field {field_name}: unsupported field type.")
            elif codec.name == "string":
                setattr(self.OT_packet, field_name, b"")
                self.write(f"Cleared {field_name}")
            else:
                setattr(self.OT_packet, field_name, 0)
                self.write(f"Cleared {field_name}")
        else:
            self.write(f"Field {field_name} not found.")
            
    def get_field(self, field_name):
        self.logger.info("Executing get_field function")
        timestamp = self.get_timestamp()
        self.echo("")
        self.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
        
        if hasattr(self.OT_packet, field_name):
            field_value = self.get_big_endian_value(self.OT_packet, field_name)
            packet_type = self.OT_packet.__class__.__name__
            field_data = [(packet_type, field_name, self.decrease_font_size(str(field_value)))]
            
            # self.echo(f"{field_name}: {field_value}")
        elif hasattr(self.TO_packet, field_name):
            field_value = self.get_big_endian_value(self.TO_packet, field_name)
            packet_type = self.TO_packet.__class__.__name__
            field_data = [(packet_type, field_name, self.decrease_font_size(str(field_value)))]
            
            # self.echo(f"{field_name}: {field_value}")
        else:
            packet_type = "N/A"
            field_data = [(packet_type, field_name, "Field not found")]
            # self.echo(f"Field {field_name} not found.")
        
        #self.echo(f"\t\t\t {packet_type} \t\t\t")
        self.echo(tabulate(field_data, headers=["CIP-MSG Identifier", "Field Name", "Field Value"], tablefmt="fancy_grid"))
        self.echo("")
          
    def get_big_endian_value(self, packet, field_name):
        field = getattr(packet.__class__, field_name)
        field_value = getattr(packet, field_name)
        metadata = cip_fields.get_field_metadata(packet, field_name)
        return cip_fields.decode_field_value(
            field,
            field_value,
            packet=packet,
            metadata=metadata,
        )
    
    def print_frame(self):
        # Print timestamp
        self.write(*"=" * 50, sep="")
        self.echo("")
        timestamp = self.get_timestamp()
        self.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
        self.lock.acquire()
        class_name_OT = self.OT_packet.__class__.__name__
        field_data_OT = [(field.name, self.decrease_font_size(str(self.get_big_endian_value(self.OT_packet, field.name)))) for field in self.OT_packet.fields_desc]
        self.lock.release()
        self.echo(f"\t\t\t {class_name_OT} \t\t\t")
        self.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
        self.echo("")
        
        self.lock.acquire()
        class_name_TO = self.TO_packet.__class__.__name__
        field_data_TO = [(field.name, self.decrease_font_size(str(self.get_big_endian_value(self.TO_packet, field.name)))) for field in self.TO_packet.fields_desc]
        self.lock.release()
        self.echo(f"\t\t\t {class_name_TO} \t\t\t")
        self.echo(tabulate(field_data_TO, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
        self.echo("")
        self.write(*"=" * 50, sep="")
        
    # def print_frame(self):
    #     # Print timestamp
    #     self.write(*"=" * 50, sep="")
    #     self.echo("")
    #     timestamp = self.get_timestamp()
    #     self.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
        
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
        
    #     self.echo(f"\t\t\t {class_name_OT} \t\t\t")
    #     self.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value", "Data Type", "Offset", "Length"], tablefmt="fancy_grid"))
    #     self.echo("")
        
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
        
    #     self.echo(f"\t\t\t {class_name_TO} \t\t\t")
    #     self.echo(tabulate(field_data_TO, headers=["Field Name", "Field Value", "Data Type", "Offset", "Length"], tablefmt="fancy_grid"))
    #     self.echo("")
    #     self.write(*"=" * 50, sep="")
    
    
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
        self.echo(title_header.center(table_width))
        self.echo(tabulate(packet_table, headers=headers, colalign=colalign, tablefmt="fancy_grid"))
        self.echo("")
        
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
        self.echo("")
        try:
            while True:
                # Print timestamp
                self.write(*"=" * 50, sep="")
                self.echo("")
                timestamp = self.get_timestamp()
                self.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
                
                class_name_OT = self.OT_packet.__class__.__name__
                field_data_OT = [(field.name, self.decrease_font_size(str(getattr(self.OT_packet, field.name)))) for field in self.OT_packet.fields_desc]
                self.echo(f"\t\t\t {class_name_OT} \t\t\t")
                self.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
                self.echo("")
                
                class_name_TO = self.TO_packet.__class__.__name__
                field_data_TO = [(field.name, self.decrease_font_size(str(getattr(self.TO_packet, field.name)))) for field in self.TO_packet.fields_desc]
                self.echo(f"\t\t\t {class_name_TO} \t\t\t")
                self.echo(tabulate(field_data_TO, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
                time.sleep(refresh_rate/1000)  # Adjust the delay as needed for real-time display
                self.echo("")
                self.write(*"=" * 50, sep="")
        except KeyboardInterrupt:
            self.write("\nExiting live field data display...")
            return
   
    
    ########################################################################
    # Under Test
    ########################################################################
    
    def wave_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing wave_field function")
        self.stop_wave(field_name)
        field = getattr(self.OT_packet.__class__, field_name)
        metadata = cip_fields.get_field_metadata(self.OT_packet, field_name)
        codec = cip_fields.get_field_codec(field)
        if codec is None or codec.name != "float":
            self.write(f"Field {field_name} is not a floating point field and cannot be waved.")
            return

        try:
            max_value = float(max_value)
            min_value = float(min_value)
            period_seconds = float(period_ms) / 1000
        except (TypeError, ValueError):
            self.write(f"Field {field_name} expects numeric bounds and a valid period.")
            return

        if period_seconds <= 0:
            self.write(f"Field {field_name} requires a positive period.")
            return

        amplitude = (max_value - min_value) / 2
        offset = (max_value + min_value) / 2

        def wave_thread():
            self.logger.info("Executing wave_thread function")
            start_time = time.time()
            while not self.stop_events[field_name].is_set():
                current_time = time.time()
                elapsed_time = current_time - start_time
                wave_value = amplitude * math.sin(2 * math.pi * elapsed_time / period_seconds) + offset

                try:
                    encoded_value = cip_fields.encode_field_value(
                        field,
                        wave_value,
                        field_name=field_name,
                        packet=self.OT_packet,
                        metadata=metadata,
                    )
                except ValueError as exc:
                    self.write(str(exc))
                    break

                setattr(self.OT_packet, field_name, encoded_value)
                time.sleep(0.01)

        self.stop_events[field_name] = threading.Event()
        wave_thread_instance = threading.Thread(target=wave_thread)
        wave_thread_instance.start()
        self.write(f"Waving {field_name} from {min_value} to {max_value} every {period_ms} milliseconds.")
            
    def tria_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing tria_field function")
        self.stop_wave(field_name)
        field = getattr(self.OT_packet.__class__, field_name)
        metadata = cip_fields.get_field_metadata(self.OT_packet, field_name)
        codec = cip_fields.get_field_codec(field)
        if codec is None or codec.name != "float":
            self.write(f"Field {field_name} is not a floating point field and cannot be waved.")
            return

        try:
            max_value = float(max_value)
            min_value = float(min_value)
            period_seconds = float(period_ms) / 1000
        except (TypeError, ValueError):
            self.write(f"Field {field_name} expects numeric bounds and a valid period.")
            return

        if period_seconds <= 0:
            self.write(f"Field {field_name} requires a positive period.")
            return

        amplitude = (max_value - min_value) / 2
        offset = (max_value + min_value) / 2

        def tria_wave_thread():
            self.logger.info("Executing tria_wave_thread function")
            start_time = time.time()
            while not self.stop_events[field_name].is_set():
                current_time = time.time()
                elapsed_time = current_time - start_time
                phase = elapsed_time / period_seconds
                wave_value = (amplitude * (2 * abs(phase - math.floor(phase + 0.5)) - 1)) + offset
                try:
                    encoded_value = cip_fields.encode_field_value(
                        field,
                        wave_value,
                        field_name=field_name,
                        packet=self.OT_packet,
                        metadata=metadata,
                    )
                except ValueError as exc:
                    self.write(str(exc))
                    break

                setattr(self.OT_packet, field_name, encoded_value)
                time.sleep(0.01)

        self.stop_events[field_name] = threading.Event()
        wave_thread_instance = threading.Thread(target=tria_wave_thread)
        wave_thread_instance.start()
        self.write(f"Triangular waving {field_name} from {min_value} to {max_value} every {period_ms} milliseconds.")
            
    
    def box_field(self, field_name, max_value, min_value, period_ms, duty_cycle):
        self.logger.info("Executing box_field function")
        self.stop_wave(field_name)
        field = getattr(self.OT_packet.__class__, field_name)
        metadata = cip_fields.get_field_metadata(self.OT_packet, field_name)
        codec = cip_fields.get_field_codec(field)
        if codec is None or codec.name != "float":
            self.write(f"Field {field_name} is not a floating point field and cannot be waved.")
            return

        try:
            max_value = float(max_value)
            min_value = float(min_value)
            period_seconds = float(period_ms) / 1000
            duty_cycle = float(duty_cycle)
        except (TypeError, ValueError):
            self.write(f"Field {field_name} expects numeric bounds, duty cycle, and a valid period.")
            return

        if period_seconds <= 0:
            self.write(f"Field {field_name} requires a positive period.")
            return

        if not 0 <= duty_cycle <= 1:
            self.write(f"Duty cycle for {field_name} must be between 0.0 and 1.0.")
            return

        def box_wave_thread():
            self.logger.info("Executing box_wave_thread function")
            start_time = time.time()
            while not self.stop_events[field_name].is_set():
                current_time = time.time()
                elapsed_time = current_time - start_time
                duty_period = period_seconds * duty_cycle
                wave_value = max_value if (elapsed_time % period_seconds) < duty_period else min_value
                try:
                    encoded_value = cip_fields.encode_field_value(
                        field,
                        wave_value,
                        field_name=field_name,
                        packet=self.OT_packet,
                        metadata=metadata,
                    )
                except ValueError as exc:
                    self.write(str(exc))
                    break

                setattr(self.OT_packet, field_name, encoded_value)
                time.sleep(0.01)

        self.stop_events[field_name] = threading.Event()
        wave_thread_instance = threading.Thread(target=box_wave_thread)
        wave_thread_instance.start()
        self.write(f"Generating square wave for {field_name} with duty cycle {duty_cycle} every {period_ms} milliseconds.")
            
    def stop_all_thread(self):
        self.logger.info(f"{self.stop_all_thread.__name__}: Stopping all wave threads for domain")
        for field_name in self.stop_events:
            self.stop_events[field_name].set()
            self.echo(f"{self.stop_all_thread.__name__}: Waving for '{field_name}' has been stopped")
        self.logger.info(f"{self.stop_all_thread.__name__}: All wave threads have been successfully stopped")

            
    def stop_wave(self, field_name):
        self.logger.info("Executing stop_wave function")
        if field_name in self.stop_events and not self.stop_events[field_name].is_set():
            self.stop_events[field_name].set()
            self.echo(f"\nWaving for '{field_name}' has been stopped.\n")
            
    def print_last_logs(self):
        log_file_path = "./log/app.log"
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as log_file:
                lines = log_file.readlines()
                last_100_lines = lines[-100:]
                self.echo("Last 100 lines of app.log:")
                for line in last_100_lines:
                    self.echo(line.strip())
    
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
            self.echo("CIP communication is already running.")
            return

        if self.TO_packet_class is None or self.OT_packet_class is None:
            self.echo("CIP packets are not initialised. Run 'cip_config' first.")
            return

        if self.ip_address is None or self.user_multicast_address is None:
            self.echo("Network configuration is incomplete. Run 'test_net' first.")
            return

        ot_param, to_param = self.calculate_connection_params()
        if ot_param is None or to_param is None:
            self.echo("Unable to calculate connection parameters from the assemblies.")
            return

        params = self.sessions.ConnectionParameters(ot_param=ot_param, to_param=to_param)

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
            self.echo(str(exc))

    def stop_comm(self):
        self.logger.info(f"{self.stop_comm.__name__}: Stopping comm thread")
        if not self.session.running:
            self.echo("No active CIP communication session.")
            return

        self.session.stop()
        self.bCIPErrorOccured = self.session.error_occurred
        self.echo("CIP communication stopped.")


 
    
    def handle_input(self):
        self.logger.info("Executing handle_input function")
        # self.echo("Handle Input is Printed")
        self.help_menu()
        
        try:
            while True:
                    self.write("")
                    command = self.prompt("Enter Command").strip().split()
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
                        self.echo("Exiting !")
                        self.stop_all_thread()
                        sys.exit()
                    else:
                        self.echo("Invalid cmd")
            
        except KeyboardInterrupt:
            self.echo("Exiting !!")
            self.stop_all_thread()
            sys.exit()


def main(
    config: Optional[RunConfiguration] = None,
    *,
    ui: Optional[UserInterface] = None,
    network_configurator=cip_network.config_network,
    cli: Optional["CIPCLI"] = None,
    cli_factory: Optional[Any] = None,
) -> None:
    """Entrypoint for both interactive and scripted runs of the CLI."""

    configuration = config or RunConfiguration()
    enable_network = (
        configuration.enable_network
        if configuration.enable_network is not None
        else ENABLE_NETWORK
    )

    if cli_factory is None:
        cli_factory = lambda: CIPCLI(ui=ui, network_configurator=network_configurator)

    cmd = cli or cli_factory()
    cmd.display_banner()
    cmd.progress_bar("Initializing", 1)

    if cmd.cip_test_flag:
        if configuration.auto_continue is None:
            should_continue = cmd.confirm('Do you want to continue?', default=True)
        else:
            should_continue = configuration.auto_continue

        if not should_continue:
            cmd.echo('Exiting...')
            return

        if not cmd.cip_config(preselected_filename=configuration.cip_filename):
            main(
                config=configuration,
                ui=ui,
                network_configurator=network_configurator,
                cli_factory=cli_factory,
            )
            return

    if not cmd.cip_test_flag:
        main(
            config=configuration,
            ui=ui,
            network_configurator=network_configurator,
            cli_factory=cli_factory,
        )
        return

    if enable_network:
        if not cmd.config_network(
            ip_address=configuration.target_ip,
            multicast_address=configuration.multicast_address,
        ):
            main(
                config=configuration,
                ui=ui,
                network_configurator=network_configurator,
                cli_factory=cli_factory,
            )
            return

    cmd.handle_input()

if __name__ == "__main__":
    main()
