#!/usr/bin/env python2
#==================================================================================================#
#              FAIVELEY TRANSPORT               | No APS.....: 14282-01-90                         #
#          www.faiveleytransport.com            | Project....: Condition Based Maintenance         #
#           Hall Parc - Batiment 6A             | Customer...: Faiveley                            #
#            3,rue du 19 mars 1962              | System.....: PASS (Door and step)                #
#         92230  Gennevilliers FRANCE           | Sub System.: workstation                         #
# =================================================================================================#

#************************ FILE DESCRIPTION    *****************************************************#
#*******   (DOXYGEN Description and automatic update by SVN)       ********************************#
#* \defgroup TBD_DEFGROUP
# * \file        $URL: http://ken/svn/PORTES/PROJET/d14282_CBM/trunk/04-SW/02-WORKSTATION/02-SW_RECORDER/04-SOURCES/sw_recorder.py $
# * \brief      Title:software CIP RER NG required for d14282_CBM project
# * \author   $Author: thierry.gautier $
# * \revision    $Rev: 326 $
# * \date       $Date: 2019-05-27 14:45:07 +0200 (lun. 27 mai 2019) $
# * \par       System: Linux
# * \par      Langage:python 2
# */
#**************************************************************************************************#
#**************************************************************************************************#
# List of modules required for this script                                                         #
#**************************************************************************************************#
import logging
import os
import sys
import time
import calendar

from cip import CIP, CIP_Path

import tgv2020
from enip_udp import CIP_IO

#**************************************************************************************************#
# Local constants definitions                                                                      #
#**************************************************************************************************#
acSOFTWARE_VERSION = "01.00"

DEBUG_CIP_FRAMES=bool(False)
DEBUG_AUTOMATE=bool(False)

#10.0.1.1 done by DHCP of raspberry pi to DLC5
#this address is done by isc-dhcp-server of rasberry see /etc/dhcp/dhcpd.conf
#make sure that a good @MAC of DLC5 is set in this file (option 12 DHCP)
DCU_IP_ADDRESS="10.0.1.1"

#239.192.1.0 multicast IP address defined in the DCU CIP
#it's the starting address of multicast, see function USER_NetworkGetMulicast of embedded software
DCU_MULTICAST_IP_ADDRESS="239.192.1.3"
 
DCU_PING_CMD="ping -c 1 "+DCU_IP_ADDRESS


#**************************************************************************************************#
# Local types Definitions                                                                          #
#**************************************************************************************************#

#**************************************************************************************************#
# Exported global variables definitions                                                            #
#**************************************************************************************************#

#**************************************************************************************************#
# Internal global variables definitions                                                            #
#**************************************************************************************************#

clMPU_CIP_Server = None


class CIP_FTPAutomate(object):
    """ class uses to manage CIP / FTP
        automate to transfert CBM file from DCU to MPU (raspberry pi)"""

    STATE_WAIT_CBM_STOP_CONDITION = int(0)
    STATE_CCUPLOADREQUEST_ENABLED = int(1)
    STATE_TRANSFERT_IN_PROGRESS   = int(2)
    STATE_WAIT_CBM_RESTART        = int(3)

    def __init__(self,intPeriodInMs=int(0)):
        """ ini automate """

        #internal vars
        self.intCBMFileTansfertState = self.STATE_WAIT_CBM_STOP_CONDITION
        self.intPeriodInMs = intPeriodInMs
        self.intTimeoutInMs = int(0)
        
        #inputs
        self.CBMStopCondition = False
        self.bITransFileOk = False
        self.bITransFileNok = False

        #outputs
        self.bCCUploadRequest = False


    def __StateWaitCBMStopCondition(self):
        """state 0 wait CBM stp condition """
        if(self.CBMStopCondition):
            #enable transfert request
            self.bCCUploadRequest = True
            self.intTimeoutInMs = 2000

            #next state
            self.intCBMFileTansfertState = self.STATE_CCUPLOADREQUEST_ENABLED
        else:
           #inialize all var
           self.bCCUploadRequest = False 
           self.intTimeoutInMs = 0 
           self.intCBMFileTansfertState = self.STATE_WAIT_CBM_STOP_CONDITION         

    def __StateCCUploadRequestEnabled(self):
        """state 1 CCUploadRequest enabled """

        #wait 2 second
        if(self.intTimeoutInMs > 0):
            self.intTimeoutInMs = self.intTimeoutInMs-self.intPeriodInMs
        # timeout is elapsed
        else:
            self.bCCUploadRequest = False
            self.intCBMFileTansfertState = self.STATE_TRANSFERT_IN_PROGRESS        

        
    def __StateTransfertInProgress(self):
        """state 2 transfert in progress """
        
        #end of file transfert OK
        if(self.CBMStopCondition and self.bITransFileOk and not(self.bITransFileNok)):  
            #next state
            self.intCBMFileTansfertState = self.STATE_WAIT_CBM_RESTART
        
        #end of file transfert NOK
        if(self.CBMStopCondition and not(self.bITransFileOk) and self.bITransFileNok):  
            #next state
            self.intCBMFileTansfertState = self.STATE_WAIT_CBM_RESTART

        if(not(self.CBMStopCondition)):
            #disable transfert request
            self.bCCUploadRequest = False

            #next state
            self.intCBMFileTansfertState = self.STATE_WAIT_CBM_STOP_CONDITION

    def __StateWaitCBMRestart(self):
        """state 3 wait CBM restart"""

        #end of file transfert
        if(not(self.CBMStopCondition)):
       
            #next state
            self.intCBMFileTansfertState = self.STATE_WAIT_CBM_STOP_CONDITION
        else:
            #next state
            self.intCBMFileTansfertState = self.STATE_WAIT_CBM_RESTART        


    def ManageCBMFileTansferAutomate(self,CBMStopCondition,bITransFileOk,bITransFileNok):
        
        """ main automate to manage CBM file transfert
            this automate uses CIP IO DCUi_MPU_DATA to get CBM state and file transfert status
                               CIP IO MPU_DCUi_DATA to enable FTP transfert
            caution:it's period =CIP IO period = 100 ms
        """
        
        self.CBMStopCondition = CBMStopCondition
        self.bITransFileOk    = bITransFileOk
        self.bITransFileNok   = bITransFileNok
        
        if(self.intCBMFileTansfertState==self.STATE_WAIT_CBM_STOP_CONDITION):
            self.__StateWaitCBMStopCondition()

        elif(self.intCBMFileTansfertState==self.STATE_CCUPLOADREQUEST_ENABLED):
            self.__StateCCUploadRequestEnabled()

        elif(self.intCBMFileTansfertState==self.STATE_TRANSFERT_IN_PROGRESS):
            self.__StateTransfertInProgress()

        elif(self.intCBMFileTansfertState==self.STATE_WAIT_CBM_RESTART):
            self.__StateWaitCBMRestart()
        else:
            raise("unknow CBM file transfert automate state")

    def GetValueOfbCCUploadRequest(self):
        return(self.bCCUploadRequest)


#**************************************************************************************************#
# Local functions definition                                                                       #
#**************************************************************************************************#
def ManageCIP_IOCommuncation(clMPU_CIP_Server):  

    #automate to manage CBM file transfert between MPU and DCU
    #period = 100 ms = period of CIP IO DCU->MPU frame (T->0) ref ICD RER NG
    Automate = CIP_FTPAutomate(100)

    #alive byte used by DCU to check MPU activity
    MPU_CTCMSAlive = int(0)

    #create the two CIP IO msg between MPU and DCU
    AppData_AS_MPU_DCUi_DATA=tgv2020.AS_MPU_DCUi_DATA()
    AppData_AS_DCUi_MPU_DATA=tgv2020.AS_DCUi_MPU_DATA()
       
    CIP_AppCounter = 65500
    bCIPErrorOccured = bool(False)

    bSystemClosedAndLockedFilterer = False
    Timer = 0;

    #infinite loop to manage CIP IO DCU<->MPU until CIP error occured
    while(not(bCIPErrorOccured)):

        #wait cyclic CIP IO frame <AS_DCUi_MPU_DATA>, timeout = 0.5 ms
        pkgCIP_IO = clMPU_CIP_Server.recv_UDP_ENIP_CIP_IO(DEBUG_CIP_FRAMES,0.5)
        
        if(pkgCIP_IO != None):
            AppData_AS_DCUi_MPU_DATA = tgv2020.AS_DCUi_MPU_DATA(pkgCIP_IO.payload.load)

            if(AppData_AS_DCUi_MPU_DATA != None):
                if(DEBUG_CIP_FRAMES):
                    AppData_AS_DCUi_MPU_DATA.show()

                #get all inputs from DCU to know the state of SIL0 CBM (stopped) see ToControlCBM.c svn 517 in function bGetConditionToControlCBM
                bIOper = bool(AppData_AS_DCUi_MPU_DATA.IOper)

                if(bIOper):
                    bIZVInput = bool(AppData_AS_DCUi_MPU_DATA.IZVInput)
                    bIDoorLocked = bool(AppData_AS_DCUi_MPU_DATA.IDoorLocked)

                    #get file transfer status from DCU
                    bITransFileOk = bool(AppData_AS_DCUi_MPU_DATA.ITransFileOk)
                    bITransFileNok= bool(AppData_AS_DCUi_MPU_DATA.ITransFileNok)

                    #generate the CBM stop condition of sw SIL0
                    if(not(bIZVInput) and bIDoorLocked):
                        CBMStopCondition = True
                    else:
                        CBMStopCondition = False
                
                    #manage CBM file transfer automate
                    Automate.ManageCBMFileTansferAutomate(CBMStopCondition,bITransFileOk,bITransFileNok)
                    bCCUploadRequest = Automate.GetValueOfbCCUploadRequest()
                else:
                    bCCUploadRequest = False
           
           
                if(DEBUG_AUTOMATE):
                    print(" bIOper:"+str(bIOper)+\
                          " bIZVInput:"+str(bIZVInput)+\
                          " bIDoorLocked:"+str(bIDoorLocked)+\
                          " intCBMFileTansfertState:"+str(Automate.intCBMFileTansfertState)+\
                          " intTimeoutInMs:"+str(Automate.intTimeoutInMs)+\
                          " CBMStopCondition:"+str(CBMStopCondition)+\
                          " bCCUploadRequest:"+str(bCCUploadRequest)+\
                          " bITransFileOk:"+str(bITransFileOk)+\
                          " bITransFileNok:"+str(bITransFileNok))

                
                #fix value to enable CIP:

                #increase the MPU_CTCMSAlive
                if(MPU_CTCMSAlive>=255):
                    MPU_CTCMSAlive=0
                else:
                    MPU_CTCMSAlive = MPU_CTCMSAlive + 1 ##1 step per 100 ms = 1 step per 100 ms see ICD

                AppData_AS_MPU_DCUi_DATA.MPU_CTCMSAlive = MPU_CTCMSAlive #required by SIL0 to analyze CIP frame

                #update application data of AS_MPU_DCUi_DATA
                AppData_AS_MPU_DCUi_DATA.MPU_CDateTimeSec = calendar.timegm(time.gmtime())
                AppData_AS_MPU_DCUi_DATA.MPU_CDateTimeTick = 0

                #fix a good value to warranty no network failure , see CTN_NETInterfaceInput.c of embedded software
                AppData_AS_MPU_DCUi_DATA.MPU_CNetwVersionX=1
                AppData_AS_MPU_DCUi_DATA.MPU_CNetwVersionY=2
                AppData_AS_MPU_DCUi_DATA.MPU_CNetwVersionZ=3

                #set MPU_CTrainOper to True, to warranty no network DCU failure
                AppData_AS_MPU_DCUi_DATA.MPU_CTrainOper = True
                
                #update CCUploadRequest for FTP transfert request
                AppData_AS_MPU_DCUi_DATA.CCUploadRequest = bCCUploadRequest
                
                #Force gap filler is retracted value to avoid buzzer at the end of the closing
                AppData_AS_MPU_DCUi_DATA.CGapFillerRectracted = True
                
                #use spare to identify end of frame 0xCA 0xFE
                #used for debug with wireshark and watis (dump g_au8EPUtoDCUDataBuffer)
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1648 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1649 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1650 = 0
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1651 = 0
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1652 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1653 = 0
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1654 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1655 = 0

                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1656 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1657 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1658 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1659 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1660 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1661 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1662 = 1
                AppData_AS_MPU_DCUi_DATA.MPU_CSpareBool1663 = 0

                if(DEBUG_CIP_FRAMES):
                    AppData_AS_MPU_DCUi_DATA.show()

                #send periodically, same period than AS_xCUiiZvv_MPU
                clMPU_CIP_Server.send_UDP_ENIP_CIP_IO(CIP_Sequence_Count=CIP_AppCounter, Header=1,AppData=AppData_AS_MPU_DCUi_DATA)

                #CIP_Sequence_Count must be from 0 to 65535
                if(CIP_AppCounter<65535):
                    CIP_AppCounter=CIP_AppCounter+1
                else:
                    CIP_AppCounter=0
            else:
                print("not possible to convert CIP IO frame into AS_DCUi_MPU_DATA")
                bCIPErrorOccured = True

        else:
            print('lost communication, check multicast on raspberry pi or ethernet connection')
            bCIPErrorOccured = True

    #end while   
    return(bCIPErrorOccured)


#**************************************************************************************************#
# Exported global functions definitions                                                            #
#**************************************************************************************************#

def main():

    global MPU

    print("----------------------------------------------------------------------------------")
    print("------------------- SW_MPU0MASTER_TGV2020 version "+ acSOFTWARE_VERSION +" --------------------------")
    print("----------------------------------------------------------------------------------")

    #infinite loop
    while(True):
 
        #Wait IP connection with DCU
        PingResult = os.system(DCU_PING_CMD)
        print(PingResult)
        while(PingResult != 0):
            PingResult = os.system(DCU_PING_CMD)
            print(PingResult)

        #Connect MPU Master to DCU or SCU,
        clMPU_CIP_Server = tgv2020.Client(IPAddr=DCU_IP_ADDRESS,MulticastGroupIPaddr=DCU_MULTICAST_IP_ADDRESS)

        #no error
        if(clMPU_CIP_Server.connected):
            print("Established session {}".format(clMPU_CIP_Server.session_id))
            
            #send forward open and wait DCU response
            bForwoardOpenRspIsOK = clMPU_CIP_Server.forward_open()
            if(bForwoardOpenRspIsOK):
                print("Forward Open OK")
            else:
                print("Forward Open request failed")
            
            #manage CIP IO cyclic communication
            bCIPErrorOccured = ManageCIP_IOCommuncation(clMPU_CIP_Server)

            if(not(bCIPErrorOccured)):
                #Close CIP connection
                clMPU_CIP_Server.forward_close()
     
            #Close all sockets
            clMPU_CIP_Server.close()

        #no connected 
        else:
            print("Not able to established session")
            time.sleep(1);

    #end while


if __name__ == '__main__':
    main()
