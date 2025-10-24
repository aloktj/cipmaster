#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Thierry GAUTIER, Wabtec (based on plc.py)
#
"""Establish all what is needed to communicate with a TGV 2020 DCU"""
import logging
import socket
import struct
from typing import Any, Optional

from scapy import all as scapy_all
import os


from thirdparty.scapy_cip_enip import utils
from thirdparty.scapy_cip_enip.cip import CIP, CIP_Path, CIP_ReqConnectionManager, \
    CIP_MultipleServicePacket, CIP_ReqForwardOpen, CIP_RespForwardOpen, \
    CIP_ReqForwardClose, CIP_ReqGetAttributeList, CIP_ReqReadOtherTag

from thirdparty.scapy_cip_enip.enip_tcp import ENIP_TCP, ENIP_SendUnitData, ENIP_SendUnitData_Item, \
    ENIP_ConnectionAddress, ENIP_ConnectionPacket, ENIP_RegisterSession, ENIP_SendRRData

from thirdparty.scapy_cip_enip.enip_udp import ENIP_UDP,ENIP_UDP_Item,ENIP_UDP_SequencedAddress,CIP_IO

# Global switch to make it easy to test without sending anything
NO_NETWORK = False

logger = logging.getLogger(__name__)

# Create log directory if it doesn't exist
log_dir = "./log"
os.makedirs(log_dir, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='./log/app.log'
)


def _item_payload_bytes(payload: Any) -> bytes:
    """Return the raw bytes carried by an ENIP connected data item payload."""

    if payload is None:
        raise ValueError("empty payload")

    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)

    load = getattr(payload, "load", None)
    if isinstance(load, (bytes, bytearray)):
        return bytes(load)

    original = getattr(payload, "original", None)
    if isinstance(original, (bytes, bytearray)):
        return bytes(original)

    if isinstance(payload, scapy_all.Packet):
        return bytes(payload)

    return bytes(payload)

class AS_MPU_DCUi_DATA(scapy_all.Packet):
    """Common Industrial Protocol, I/O input
       see ICD TGV2020 (e165100-0000-e20sys Rev E0) and
       http://ken/svn/PORTES/PROJET/d7760_TGV2020/trunk/03-SW/04-SW_CPU_SIL0/03-APPLICATION/04-SOURCES/NETWORK/ControlTheNetwork.mod/alstom_icd/at-io.h rev 1062 
       """
#     name = "AS_MPU_DEV"
#     fields_desc = [
#         # Signals with boolean values
#         scapy_all.BitField("MPU_CTCMSAlive", 0, 8),
#         scapy_all.BitField("MPU_CMaintModeAuth", 0, 1),
#         scapy_all.BitField("MPU_CReprogModeAuth", 0, 1),
#         scapy_all.BitField("MPU_COnDmdTestResume", 0, 1),
#         scapy_all.BitField("BCHi_COnDmdTestStart", 0, 1),
#         scapy_all.BitField("MPU_CGpsValidity", 0, 1),
#         # Filler to ensure boolean values are packed together
#         scapy_all.StrFixedLenField("bool_filler1", b"", length=4),
#         # Signals with non-boolean values
#         scapy_all.IntField("MPU_CDateTimeSec", 0),
#         scapy_all.IntField("MPU_CTrainNum", 0),
#         scapy_all.IEEEFloatField("MPU_CSpeed", 0.0),
#         scapy_all.ByteField("MPU_COperSt", 0),
#         scapy_all.ByteField("MPU_CNumOfTrainSetsMU", 0),
#         scapy_all.ByteField("MPU_CTrainSetPosNum", 0),
#         scapy_all.ByteField("MPU_CCarPosNum", 0),
#         scapy_all.StrFixedLenField("BCHi_CMaintLang", b"", length=2),
#         scapy_all.StrFixedLenField("MPU_CTrainSetType", b"", length=12),
#         scapy_all.StrFixedLenField("MPU_CTrainSetId", b"", length=12),
#         scapy_all.StrFixedLenField("MPU_CTrainSetIDUx", b"", length=12),
#         scapy_all.StrFixedLenField("MPU_CCarId", b"", length=12),
#         scapy_all.IEEEFloatField("MPU_CLatitude", 0.0),
#         scapy_all.IEEEFloatField("MPU_CLongitude", 0.0),
#         scapy_all.ByteField("BCHi_CBchEqtNum", 0),
#         # Filler to ensure proper alignment
#         scapy_all.StrFixedLenField("filler1", b"", length=4),
#     ]
    fields_desc = [
        scapy_all.ByteField("MPU_CTCMSAlive",0),                #0
        scapy_all.LEIntField("MPU_CDateTimeSec",0),             #8
        
        scapy_all.LEShortField("MPU_CTrainNum",0),              #16
        # scapy_all.BitField("MPU_CMaintModeAuth",0, 8),          #48
        # scapy_all.BitField("MPU_CReprogModeAuth",0, 1),         #64
        # scapy_all.BitField("MPU_COnDmdTestResume",0, 1),        #72
        # scapy_all.ByteField("BCHi_CMaintLang",0),               #80
        # scapy_all.BitField("BCHi_COnDmdTestStart",0, 1),        #88
        scapy_all.IEEEFloatField("MPU_CSpeed",0),               #96
        scapy_all.ByteField("MPU_COperSt", 0),                  #112
        scapy_all.ByteField("MPU_CNumOfTrainSetsMU", 0),        #113
        scapy_all.ByteField("MPU_CTrainSetPosNum", 0),          #114
        scapy_all.ByteField("MPU_CTrainSetType", 0),            #115
        scapy_all.ByteField("MPU_CTrainSetId", 0),              #116
        scapy_all.ByteField("MPU_CTrainSetIDUx", 0),            #117
        scapy_all.ByteField("MPU_CCarId", 0),                   #118
        scapy_all.IEEEFloatField("MPU_CLatitude", 0),           #119
        scapy_all.IEEEFloatField("MPU_CLongitude",0),           #120
        scapy_all.ByteField("BCHi_CBchEqtNum",0),               #128
        scapy_all.ByteField("BCHi_CBattSOCMaxAck",0),           #136
        # scapy_all.BitField("BCHi_CBchInhibReq",0, 1),           #144
        # scapy_all.BitField("BCHi_CBchChargingAuth",0, 1),       #152
        # scapy_all.BitField("BCHi_CBchAtleastOneLoss",0, 1),     #160
        # scapy_all.BitField("BCHi_CBchOnDmdSafetyTestStart",0, 1), #168
        # scapy_all.BitField("BCHi_CBchFltAck",0, 1),             #176
        # scapy_all.BitField("BCHi_CBchFltRst",0, 1)              #184
    ]

    
class AS_DCUi_MPU_DATA(scapy_all.Packet):
    """Common Industrial Protocol, I/O input
       see ICD TGV2020 (e165100-0000-e20sys Rev E0) and
       http://ken/svn/PORTES/PROJET/d7760_TGV2020/trunk/03-SW/04-SW_CPU_SIL0/03-APPLICATION/04-SOURCES/NETWORK/ControlTheNetwork.mod/alstom_icd/at-io.h rev: 1062 
       """
    name = "AS_DCUi_MPU_DATA"
    fields_desc = [
        scapy_all.ByteField("BCHi_IDevIsAlive",0),             #0
        scapy_all.ByteField("BCHi_INetwVersionX",0),           #8
        scapy_all.ByteField("BCHi_INetwVersionY",0),           #16
        scapy_all.ByteField("BCHi_INetwVersionZ",0),           #24
        scapy_all.ByteField("BCHi_ISwVersionX",0),             #32
        scapy_all.ByteField("BCHi_ISwVersionY",0),             #40
        scapy_all.ByteField("BCHi_ISwVersionZ",0),             #48
        scapy_all.ByteField("BCHi_IHwVersionX",0),             #56
        scapy_all.ByteField("BCHi_IHwVersionY",0),             #64
        scapy_all.ByteField("BCHi_IHwVersionZ",0),             #72
        scapy_all.LEShortField("BCHi_ISerialNum",0),           #80
        scapy_all.BitField("BCHi_IOper", 0, 1),                #96
        scapy_all.BitField("BCHi_IMajorFltPres", 0, 1),        #97
        scapy_all.BitField("BCHi_IMinorFltPres", 0, 1),        #98
        scapy_all.BitField("BCHi_IInformFltPres", 0, 1),       #99
        scapy_all.BitField("BCHi_IEqtInMaint", 0, 1),          #100
        scapy_all.BitField("BCHi_IOnDmdTestInP", 0, 1),        #101
        scapy_all.BitField("BCHi_IOnDmdTestDone", 0, 1),       #102
        scapy_all.BitField("BCHi_IOnDmdTestOk", 0, 1),         #103
        # scapy_all.BitField("BCHi_IAutoTestDone", 0, 1),        #104
        # scapy_all.BitField("BCHi_IAutoTestOk", 0, 1),          #105
        # scapy_all.IEEEFloatField("BCHi_IBchVoltageLine", 0),   #128
        # scapy_all.IEEEFloatField("BCHi_IBchCurrentLine", 0),   #160
        # scapy_all.IEEEFloatField("BCHi_IBchVoltageIn", 0),     #192
        # scapy_all.IEEEFloatField("BCHi_IBchCurrentIn", 0),     #224
        # scapy_all.IEEEFloatField("BCHi_IBchVoltagePS", 0),     #256
        # scapy_all.IEEEFloatField("BCHi_IBchCurrentPS", 0),     #288
        # scapy_all.IEEEFloatField("BCHi_IBchTemp", 0),          #320
        # scapy_all.LEIntField("BCHi_IBattCustomer1", 0),        #352
        # scapy_all.IEEEFloatField("BCHi_IBchVoltageBatt", 0),   #384
        # scapy_all.IEEEFloatField("BCHi_IBchCurrentBatt", 0),   #416   
        # scapy_all.LEShortField("BCHi_IBattVCellMax", 0),       #1152        
        # scapy_all.LEShortField("BCHi_IBattVCellMin", 0),       #1168        
        # scapy_all.LEShortField("BCHi_IBattVCellAvg", 0),       #1184        
        # scapy_all.LEShortField("BCHi_IBattIntVoltage", 0),     #1200        
        # scapy_all.ByteField("BCHi_IBattIntCurrent", 0),        #1408
        # scapy_all.ByteField("BCHi_ISwGWVersionX", 0),          #1416
        # scapy_all.ByteField("BCHi_ISwGWVersionY", 0),          #1424      
        # scapy_all.ByteField("BCHi_ISwGWVersionZ", 0),          #1432      
        # scapy_all.LEShortField("BCHi_IBattIMRC", 0),           #1200        
        # scapy_all.LEShortField("BCHi_IBattIMD", 0),            #1200        
        # scapy_all.LEShortField("BCHi_IBattPMD", 0),            #1200
        # scapy_all.ByteField("BCHi_IBattSystMode", 0),          #1408
        # scapy_all.ByteField("BCHi_IBattSOH", 0),               #1408
        # scapy_all.ByteField("BCHi_IBattGblStatus", 0),         #1408
        # scapy_all.ByteField("BCHi_IBattFltCodStatus", 0),      #1408
        # scapy_all.ByteField("BCHi_IBattSOCMax", 0),            #1408
        # scapy_all.ByteField("BCHi_IBattMaxTemp", 0),           #1408
        # scapy_all.ByteField("BCHi_IBattSOC", 0),               #1408
        # scapy_all.ByteField("BCHi_IBchGeneralStatus", 0),      #1408
        # scapy_all.BitField("BCHi_IBchSafetyCardLVDet", 0, 1),  #105
        # scapy_all.BitField("BCHi_IBchSafetyCardHVDet", 0, 1),  #105
        # scapy_all.BitField("BCHi_IBchSafetyTestInP", 0, 1),    #105
        # scapy_all.BitField("BCHi_IBchSafetyTestOk", 0, 1),     #105
        # scapy_all.BitField("BCHi_IBchCVSRunning", 0, 1),       #105
        # scapy_all.BitField("BCHi_IBchComLostWithBatt", 0, 1),  #105
        # scapy_all.BitField("BCHi_IBchReducPwr", 0, 1),         #105
        # scapy_all.BitField("BCHi_IBchReducPwr320VAC", 0, 1)    #105 
    ]

    
class Client(object):
    
    """Handle all the state of an Ethernet/IP session with a RER NG project"""
    def __init__(self,
                 IPAddr='10.0.1.1',
                 MulticastGroupIPaddr='239.192.1.3'):

        self.PortEtherNetIPExplicitMessage = 44818 #TCP and UDP
        self.PortEtherNetIPImplicitMessageIO = 2222 #TCP and UDP
        self.ot_connection_param = None
        self.to_connection_param = None
        self.logger = logging.getLogger(self.__class__.__name__)

        """ create two IP connection,
            - first:to manage CIP unicast of DCU TGV2020 (TCP and UDP) ,
            - second:to manage CIP multicast frame (224.0.0.0/4 RFC5771) only UDP due to multicast"""
        self._local_ip: Optional[str] = None

        if not NO_NETWORK:
            #open connection with DCU
            try:
                # print("DEBUG:5.1")
                self.Sock = socket.create_connection((IPAddr, self.PortEtherNetIPExplicitMessage))
                # print("DEBUG:5.2")
            except socket.error as exc:
                # print("DEBUG:5.3")
                logger.warn("socket error: %s", exc)
                logger.warn("Continuing without sending anything")
                self.Sock = None
            else:
                try:
                    self._local_ip = self.Sock.getsockname()[0]
                    self.logger.debug(
                        "Detected local interface %s for CIP session", self._local_ip
                    )
                except OSError as exc:
                    self.logger.debug(
                        "Unable to determine local interface for CIP session: %s", exc
                    )
                    self._local_ip = None

            #open connection to the multicast group
            try:
                # print("DEBUG:5.4")
                # Create the socket
                self.MulticastSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                try:
                    self.MulticastSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except OSError as exc:
                    self.logger.debug(
                        "Unable to enable SO_REUSEADDR on multicast socket: %s", exc
                    )

                # print("DEBUG:5.5")
                # Bind to the server address
                self.MulticastSock.bind(('',self.PortEtherNetIPImplicitMessageIO))

                # print("DEBUG:5.6")
                # Tell the operating system to add the socket to the multicast group
                # on all interfaces.
                group = socket.inet_aton(MulticastGroupIPaddr)
                # print("DEBUG:5.7")
                interface_ip: Optional[bytes] = None
                if self._local_ip:
                    try:
                        interface_ip = socket.inet_aton(self._local_ip)
                    except OSError:
                        interface_ip = None

                joined = False

                if interface_ip is not None:
                    try:
                        self.MulticastSock.setsockopt(
                            socket.IPPROTO_IP,
                            socket.IP_MULTICAST_IF,
                            interface_ip,
                        )
                    except OSError as exc:
                        self.logger.debug(
                            "Unable to select multicast interface %s: %s",
                            self._local_ip,
                            exc,
                        )

                    try:
                        mreq = struct.pack('4s4s', group, interface_ip)
                        self.MulticastSock.setsockopt(
                            socket.IPPROTO_IP,
                            socket.IP_ADD_MEMBERSHIP,
                            mreq,
                        )
                    except OSError as exc:
                        self.logger.warning(
                            "Failed to join multicast group %s on interface %s",
                            MulticastGroupIPaddr,
                            self._local_ip,
                        )
                        self.logger.debug("Membership error details", exc_info=True)
                    else:
                        joined = True

                if not joined:
                    try:
                        mreq_any = struct.pack('4sL', group, socket.INADDR_ANY)
                        self.MulticastSock.setsockopt(
                            socket.IPPROTO_IP,
                            socket.IP_ADD_MEMBERSHIP,
                            mreq_any,
                        )
                    except OSError as exc:
                        logger.warn("Not possible to manage multicast group ip address: %s", exc)
                        self.MulticastSock = None
                    else:
                        self.logger.debug(
                            "Joined multicast group %s using INADDR_ANY fallback",
                            MulticastGroupIPaddr,
                        )
                # print("DEBUG:5.9")
            except:
                # print("DEBUG:5.10")
                logger.warn("Not possible to manage multicast group ip address")
                self.MulticastSock = None

            #open connection with DCU TODO
            try:
                # print("DEBUG:5.11")
                self.Sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # print("DEBUG:5.12")
                self.Sock1.connect((IPAddr, self.PortEtherNetIPImplicitMessageIO))
                # print("DEBUG:5.13")
            except socket.error as exc:
                # print("DEBUG:5.14")
                logger.warn("socket error: %s", exc)
                logger.warn("Continuing without sending anything --")
                self.Sock1 = None
        else:
            # print("DEBUG:5.16")
            self.Sock = None
            self.MulticastSock = None
            self.Sock1 = None
        
        # print("DEBUG:5.17")
        self.session_id = 0
        self.enip_connection_id_OT = 0 #required for CIP IO O->T
        self.enip_connection_id_TO = 0 #required for CIP IO T->O
        self.sequence_unit_cip = 1
        self.sequence_CIP_IO = 1

        # Open an Ethernet/IP session
        sessionpkt = ENIP_TCP() / ENIP_RegisterSession()
        # print("DEBUG:5.18")
        if self.Sock is not None:
            # print("DEBUG:5.19")
            self.Sock.send(scapy_all.raw(sessionpkt))
            # print("DEBUG:5.20")
            reply_pkt = self.recv_enippkt()
            # print("DEBUG:5.21")
            self.session_id = reply_pkt.session
            # print("DEBUG:5.22")



    def close(self):
        """Close all sockets open during the init."""

        sock = getattr(self, "Sock", None)
        if sock is not None:
            try:
                sock.close()
            except OSError as exc:
                self.logger.debug("Error while closing TCP socket: %s", exc)
            finally:
                self.Sock = None

        multicast_sock = getattr(self, "MulticastSock", None)
        if multicast_sock is not None:
            try:
                multicast_sock.close()
            except OSError as exc:
                self.logger.debug("Error while closing multicast socket: %s", exc)
            finally:
                self.MulticastSock = None

        udp_sock = getattr(self, "Sock1", None)
        if udp_sock is not None:
            try:
                udp_sock.close()
            except OSError as exc:
                self.logger.debug("Error while closing UDP socket: %s", exc)
            finally:
                self.Sock1 = None
        

    @property
    def connected(self):
        return True if self.Sock else False

    def send_rr_cip(self, cippkt):
        """Send a CIP packet over the TCP connection as an ENIP Req/Rep Data"""
        enippkt = ENIP_TCP(session=self.session_id)
        enippkt /= ENIP_SendRRData(items=[
            ENIP_SendUnitData_Item(type_id=0),
            ENIP_SendUnitData_Item() / cippkt
        ])
        if self.Sock is not None:
            self.Sock.send(scapy_all.raw(enippkt))

    def send_rr_cm_cip(self, cippkt):
        """Encapsulate the CIP packet into a ConnectionManager packet"""
        cipcm_msg = [cippkt]
        cippkt = CIP(path=CIP_Path.make(class_id=6, instance_id=1))
        cippkt /= CIP_ReqConnectionManager(message=cipcm_msg)
        self.send_rr_cip(cippkt)

    def send_rr_mr_cip(self, cippkt):
        """Encapsulate the CIP packet into a MultipleServicePacket to MessageRouter"""
        cipcm_msg = [cippkt]
        cippkt = CIP(path=CIP_Path(wordsize=2, path=b'\x20\x02\x24\x01'))
        cippkt /= CIP_MultipleServicePacket(packets=cipcm_msg)
        self.send_rr_cip(cippkt)

    def send_unit_cip(self, cippkt):
        """Send a CIP packet over the TCP connection as an ENIP Unit Data"""
        enippkt = ENIP_TCP(session=self.session_id)
        enippkt /= ENIP_SendUnitData(items=[
            ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=self.enip_connection_id_OT),
            ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=self.sequence_unit_cip) / cippkt
        ])
        self.sequence_unit_cip += 1
        if self.Sock is not None:
            self.Sock.send(scapy_all.raw(enippkt))

    def recv_enippkt(self):
        """Receive an ENIP packet from the TCP socket"""
        self.logger.info("TGV2020: recv_enippkt executing")
        if self.Sock is None:
            self.logger.warning("TGV2020: recv_enippkt: self.sock is None")
            return
        pktbytes = self.Sock.recv(2000)
        pkt = ENIP_TCP(pktbytes)
        self.logger.info("TGV2020: recv_enippkt: returning enip_tcp packet received")
        return pkt

    def recv_UDP_ENIP_CIP_IO(self,DEBUG=bool(False),Timeout=0):
        """receive cyclic mulicast CIP IO like <AS_DCUi_MPU_DATA>"""
        
        self.logger.info("TGV2020: recv_UDP_ENIP_CIP_IO executing")
        
        if self.MulticastSock is None:
            self.logger.warning("TGV2020: recv_UDP_ENIP_CIP_IO: self.MulticastSock is None")
            # print("DEBUG: Multicast sock is None")
            return None
        
        #fix timeout
        self.MulticastSock.settimeout(Timeout)
        self.logger.info("TGV2020: recv_UDP_ENIP_CIP_IO: Multicast timeout set")
        
        #wait CIP IO frame during Timeout
        try:
            (pktbytes, address) = self.MulticastSock.recvfrom(2000)
        except socket.timeout:
            self.logger.warning("TGV2020: recv_UDP_ENIP_CIP_IO: NO CIP_IO packet is returned")
            return None
        except OSError as exc:
            self.logger.warning(
                "TGV2020: recv_UDP_ENIP_CIP_IO: socket error while waiting for CIP IO",
                exc_info=self.logger.isEnabledFor(logging.DEBUG),
            )
            return None

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                "TGV2020: recv_UDP_ENIP_CIP_IO: received %d bytes from %s:%s\n%s",
                len(pktbytes),
                address[0],
                address[1],
                utils.hexdump(pktbytes),
            )

        try:
            pkt_udp = ENIP_UDP(pktbytes)
        except Exception:
            self.logger.warning(
                "TGV2020: recv_UDP_ENIP_CIP_IO: failed to decode ENIP UDP payload",
                exc_info=self.logger.isEnabledFor(logging.DEBUG),
            )
            return None

        if(DEBUG):
            pkt_udp.show()

        connected_item: Optional[ENIP_UDP_Item] = None
        sequenced_item: Optional[ENIP_UDP_Item] = None
        items = getattr(pkt_udp, "items", []) or []
        for item in items:
            if item.type_id in (0x00B1, "Connected_Data_Item"):
                connected_item = item
            elif item.type_id in (0x8002, "Sequenced_Address") and sequenced_item is None:
                sequenced_item = item

        if connected_item is None:
            self.logger.debug(
                "TGV2020: recv_UDP_ENIP_CIP_IO: ignoring packet without Connected_Data_Item (items=%s)",
                [
                    f"0x{int(item.type_id):04x}" if isinstance(item.type_id, int) else str(item.type_id)
                    for item in items
                ],
            )
            return None

        if sequenced_item is not None:
            connection_id = getattr(sequenced_item.payload, "connection_id", None)
            expected_ids = tuple(
                cid
                for cid in (self.enip_connection_id_TO, self.enip_connection_id_OT)
                if cid
            )
        else:
            connection_id = None
            expected_ids = ()

        if connection_id not in (None,) + expected_ids and expected_ids:
            self.logger.debug(
                "TGV2020: recv_UDP_ENIP_CIP_IO: sequenced connection id 0x%04x does not match expected %s",
                connection_id or 0,
                ", ".join(f"0x{cid:04x}" for cid in expected_ids) or "<none>",
            )

        try:
            payload_bytes = _item_payload_bytes(connected_item.payload)
        except Exception:
            self.logger.warning(
                "TGV2020: recv_UDP_ENIP_CIP_IO: unable to obtain connected item payload",
                exc_info=self.logger.isEnabledFor(logging.DEBUG),
            )
            return None

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                "TGV2020: recv_UDP_ENIP_CIP_IO: connected payload (%d bytes)\n%s",
                len(payload_bytes),
                utils.hexdump(payload_bytes),
            )

        try:
            pkgCIP_IO = CIP_IO(payload_bytes)
        except Exception:
            self.logger.warning(
                "TGV2020: recv_UDP_ENIP_CIP_IO: failed to decode CIP_IO payload",
                exc_info=self.logger.isEnabledFor(logging.DEBUG),
            )
            return None

        if(DEBUG):
            pkgCIP_IO.show()

        self.logger.info("TGV2020: recv_UDP_ENIP_CIP_IO: CIP_IO packet is returned")
        return pkgCIP_IO


    def send_UDP_ENIP_CIP_IO(self,CIP_Sequence_Count=0,Header=0,AppData=None):
        """send cyclic unicast CIP IO like <AS_MPU_DCUi_DATA>"""
        self.logger.info("TGV2020: send_UDP_ENIP_CIP_IO executing")
        enippkt = ENIP_UDP(count=2,items=[
            ENIP_UDP_Item(type_id="Sequenced_Address",length=8) / ENIP_UDP_SequencedAddress(connection_id=self.enip_connection_id_OT, sequence=self.sequence_CIP_IO),
            ENIP_UDP_Item(type_id="Connected_Data_Item",length=len(AppData)+len(CIP_IO()))
        ])
        #add CIP IO part
        enippkt /= CIP_IO(CIP_Sequence_Count=CIP_Sequence_Count,Header=Header)
        
        #add data application part of the project
        enippkt /= AppData

        #enippkt.show()
        self.sequence_CIP_IO += 1
        self.logger.info(f"TGV2020: send_UDP_ENIP_CIP_IO: sequence_CIP_IO {self.sequence_CIP_IO}")
        if self.Sock1 is not None:
            self.logger.info("TGV2020: send_UDP_ENIP_CIP_IO: Sending UDP_ENIP_CIP_IO through socket")
            self.Sock1.send(scapy_all.raw(enippkt))
        else:
            self.logger.warning("TGV2020: send_UDP_ENIP_CIP_IO: Socket error: failed to send UDP_ENIP_CIP_IO")

    def _cip_status_ok(self, cippkt, context):
        status_code, status_obj = utils.cip_status_details(cippkt)
        if status_code != 0:
            logger.error("%s: %r", context, status_obj or status_code)
            return False
        if status_obj is None:
            self.logger.debug("%s: CIP response omitted status; assuming success", context)
        return True

    def forward_open(self):
        """Send a forward open request"""
        self.logger.info("TGV2020: forward_open executing")
        cippkt = CIP(service=0x54, path=CIP_Path(wordsize=2, path=b'\x20\x06\x24\x01'))
        cippkt /= CIP_ReqForwardOpen(connection_path_size=9, connection_path=b"\x34\x04\x00\x00\x00\x00\x00\x00\x00\x00\x20\x04\x24\x01\x2C\x65\x2C\x64",
                                     OT_connection_param=self.ot_connection_param, TO_connection_param=self.to_connection_param)
        self.send_rr_cip(cippkt)
        resppkt = self.recv_enippkt()
        if self.Sock is None:
            self.logger.warning("TGV2020: forward_open: Socket Error: Socket was found close")
            return
        cippkt = resppkt[CIP]
    
        if not self._cip_status_ok(cippkt, "Failed to Forward Open CIP connection"):
            return False
        assert isinstance(cippkt.payload, CIP_RespForwardOpen)
        self.enip_connection_id_OT = cippkt.payload.OT_network_connection_id
        self.enip_connection_id_TO = cippkt.payload.TO_network_connection_id
        return True

    def forward_close(self):
        """Send a forward close request"""
        cippkt = CIP(service=0x4e, path=CIP_Path(wordsize=2, path=b'\x20\x06\x24\x01'))
        cippkt /= CIP_ReqForwardClose(connection_path_size=9, connection_path=b"\x34\x04\x00\x00\x00\x00\x00\x00\x00\x00\x20\x04\x24\x01\x2C\x65\x2C\x64")
        self.send_rr_cip(cippkt)
        if self.Sock is None:
            return
        resppkt = self.recv_enippkt()
        cippkt = resppkt[CIP]
        
        if not self._cip_status_ok(cippkt, "Failed to Forward Close CIP connection"):
            return False

        return True

    def get_attribute(self, class_id, instance, attr):
        """Get an attribute for the specified class/instance/attr path"""
        # Get_Attribute_Single does not seem to work properly
        # path = CIP_Path.make(class_id=class_id, instance_id=instance, attribute_id=attr)
        # cippkt = CIP(service=0x0e, path=path)  # Get_Attribute_Single
        path = CIP_Path.make(class_id=class_id, instance_id=instance)
        cippkt = CIP(path=path) / CIP_ReqGetAttributeList(attrs=[attr])
        self.send_rr_cm_cip(cippkt)
        if self.Sock is None:
            return
        resppkt = self.recv_enippkt()
        cippkt = resppkt[CIP]
        
        if not self._cip_status_ok(cippkt, "CIP get attribute error"):
            return
        resp_getattrlist = str(cippkt.payload)
        assert resp_getattrlist[:2] == b'\x01\x00'  # Attribute count must be 1
        assert struct.unpack('<H', resp_getattrlist[2:4])[0] == attr  # First attribute
        assert resp_getattrlist[4:6] == b'\x00\x00'  # Status
        return resp_getattrlist[6:]

    def set_attribute(self, class_id, instance, attr, value):
        """Set the value of attribute class/instance/attr"""
        path = CIP_Path.make(class_id=class_id, instance_id=instance)
        # User CIP service 4: Set_Attribute_List
        cippkt = CIP(service=4, path=path) / scapy_all.Raw(load=struct.pack('<HH', 1, attr) + value)
        self.send_rr_cm_cip(cippkt)
        if self.Sock is None:
            return
        resppkt = self.recv_enippkt()
        cippkt = resppkt[CIP]
        
        if not self._cip_status_ok(cippkt, "CIP set attribute error"):
            return False
        return True

    def get_list_of_instances(self, class_id):
        """Use CIP service 0x4b to get a list of instances of the specified class"""
        start_instance = 0
        inst_list = []
        while True:
            cippkt = CIP(service=0x4b, path=CIP_Path.make(class_id=class_id, instance_id=start_instance))
            self.send_rr_cm_cip(cippkt)
            if self.Sock is None:
                return
            resppkt = self.recv_enippkt()

            # Decode a list of 32-bit integers
            data = str(resppkt[CIP].payload)
            for i in range(0, len(data), 4):
                inst_list.append(struct.unpack('<I', data[i:i + 4])[0])
            
            cipstatus, status_obj = utils.cip_status_details(resppkt[CIP])
            if cipstatus == 0:
                return inst_list
            elif cipstatus == 6:
                # Partial response, query again from the next instance
                start_instance = inst_list[-1] + 1
            else:
                logger.error("Error in Get Instance List response: %r", status_obj or cipstatus)
                return

    def read_full_tag(self, class_id, instance_id, total_size):
        """Read the content of a tag which can be quite big"""
        data_chunks = []
        offset = 0
        remaining_size = total_size

        while remaining_size > 0:
            cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=class_id, instance_id=instance_id))
            cippkt /= CIP_ReqReadOtherTag(start=offset, length=remaining_size)
            self.send_rr_cm_cip(cippkt)
            if self.Sock is None:
                return
            resppkt = self.recv_enippkt()
            
            cipstatus, status_obj = utils.cip_status_details(resppkt[CIP])
            received_data = str(resppkt[CIP].payload)
            if cipstatus == 0:
                # Success
                assert len(received_data) == remaining_size
            elif cipstatus == 6 and len(received_data) > 0:
                # Partial response (size too big)
                pass
            else:
                logger.error("Error in Read Tag response: %r", status_obj or cipstatus)
                return

            # Remember the chunk and continue
            data_chunks.append(received_data)
            offset += len(received_data)
            remaining_size -= len(received_data)
            
        return b''.join(data_chunks)

    @staticmethod
    def attr_format(attrval):
        """Format an attribute value to be displayed to a human"""
        if len(attrval) == 1:
            # 1-byte integer
            return hex(struct.unpack('B', attrval)[0])
        elif len(attrval) == 2:
            # 2-byte integer
            return hex(struct.unpack('<H', attrval)[0])
        elif len(attrval) == 4:
            # 4-byte integer
            return hex(struct.unpack('<I', attrval)[0])
        elif all(x == b'\0' for x in attrval):
            # a series of zeros
            return '[{} zeros]'.format(len(attrval))
        # format in hexadecimal the content of attrval
        return ''.join('{:2x}'.format(ord(x)) for x in attrval)




