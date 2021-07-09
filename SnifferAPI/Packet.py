# Copyright (c) 2017, Nordic Semiconductor ASA
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
#    3. Neither the name of Nordic Semiconductor ASA nor the names of
#       its contributors may be used to endorse or promote products
#       derived from this software without specific prior written
#       permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NORDIC
# SEMICONDUCTOR ASA OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

from . import UART, Exceptions, Notifications
import time, logging, os, sys, serial
from .Types import *

ADV_ACCESS_ADDRESS = [0xD6, 0xBE, 0x89, 0x8E]

SYNCWORD_POS = 0
PAYLOAD_LEN_POS_V1 = 1
PAYLOAD_LEN_POS = 0
PROTOVER_POS = PAYLOAD_LEN_POS+2
PACKETCOUNTER_POS = PROTOVER_POS+1
ID_POS = PACKETCOUNTER_POS+2

BLE_HEADER_LEN_POS = ID_POS+1
FLAGS_POS = BLE_HEADER_LEN_POS+1
CHANNEL_POS = FLAGS_POS+1
RSSI_POS = CHANNEL_POS+1
EVENTCOUNTER_POS = RSSI_POS+1
TIMESTAMP_POS = EVENTCOUNTER_POS+2
BLEPACKET_POS = TIMESTAMP_POS+4
TXADD_POS = BLEPACKET_POS + 4
TXADD_MSK = 0x40
PAYLOAD_POS = BLE_HEADER_LEN_POS

HEADER_LENGTH = 6
BLE_HEADER_LENGTH = 10

VALID_ADV_CHANS = [37, 38, 39]

PACKET_COUNTER_CAP = 2**16


class PacketReader(Notifications.Notifier):
    def __init__(self, portnum=None, callbacks=[], baudrate=None):
        Notifications.Notifier.__init__(self, callbacks)
        self.portnum = portnum
        try:
            self.uart = UART.Uart(portnum, baudrate)
        except serial.SerialException as e:
            logging.exception("Error opening UART.")
            self.uart = UART.Uart()
        self.packetCounter = 0
        self.lastReceivedPacketCounter = 0
        self.lastReceivedPacket = None

    def setup(self):
        pass

    def doExit(self):
        # This method will always join the Uart worker thread
        self.uart.close()
        # Clear method references to avoid uncollectable cyclic references
        self.clearCallbacks()

    # This function takes a byte list, encode it in SLIP protocol and return the encoded byte list
    def encodeToSLIP(self, byteList):
        tempSLIPBuffer = []
        tempSLIPBuffer.append(SLIP_START)
        for i in byteList:
            if i == SLIP_START:
                tempSLIPBuffer.append(SLIP_ESC)
                tempSLIPBuffer.append(SLIP_ESC_START)
            elif i == SLIP_END:
                tempSLIPBuffer.append(SLIP_ESC)
                tempSLIPBuffer.append(SLIP_ESC_END)
            elif i == SLIP_ESC:
                tempSLIPBuffer.append(SLIP_ESC)
                tempSLIPBuffer.append(SLIP_ESC_ESC)
            else:
                tempSLIPBuffer.append(i)
        tempSLIPBuffer.append(SLIP_END)
        return tempSLIPBuffer

    # This function uses getSerialByte() function to get SLIP encoded bytes from the serial port and return a decoded byte list  
    # Based on https://github.com/mehdix/pyslip/
    def decodeFromSLIP(self, timeout=None, complete_timeout=None):
        dataBuffer = []
        startOfPacket = False
        endOfPacket = False

        if complete_timeout is not None:
            time_start = time.time()

        while not startOfPacket and (complete_timeout is None or (time.time() - time_start < complete_timeout)):
            res = self.getSerialByte(timeout)
            startOfPacket = (res == SLIP_START)

        while not endOfPacket and (complete_timeout is None or (time.time() - time_start < complete_timeout)):
            serialByte = self.getSerialByte(timeout)
            if serialByte == SLIP_END:
                endOfPacket = True
            elif serialByte == SLIP_ESC:
                serialByte = self.getSerialByte(timeout)
                if serialByte == SLIP_ESC_START:
                    dataBuffer.append(SLIP_START)
                elif serialByte == SLIP_ESC_END:
                    dataBuffer.append(SLIP_END)
                elif serialByte == SLIP_ESC_ESC:
                    dataBuffer.append(SLIP_ESC)
                else:
                    dataBuffer.append(SLIP_END)
            else:
                 dataBuffer.append(serialByte)
        if not endOfPacket:
            raise Exceptions.UARTPacketError("Exceeded max timeout of %f seconds." % complete_timeout)
        return dataBuffer

    # This function read byte chuncks from the serial port and return one byte at a time
    # Based on https://github.com/mehdix/pyslip/
    def getSerialByte(self, timeout=None):
        serialByte = self.uart.readByte(timeout)
        if serialByte is None:
            raise Exceptions.SnifferTimeout("Packet read timed out.")
        return serialByte

    def handlePacketHistory(self, packet):
        # Reads and validates packet counter
        if self.lastReceivedPacket is not None \
                and packet.packetCounter != (self.lastReceivedPacket.packetCounter + 1) % PACKET_COUNTER_CAP \
                and self.lastReceivedPacket.packetCounter != 0:

            logging.info("gap in packets, between " + str(self.lastReceivedPacket.packetCounter) + " and "
                         + str(packet.packetCounter) + " packet before: " + str(self.lastReceivedPacket.packetList)
                         + " packet after: " + str(packet.packetList))
        self.lastReceivedPacket = packet

    def getPacket(self, timeout=None):
        packetList = []
        try:
            packetList = self.decodeFromSLIP(timeout)
        except Exceptions.UARTPacketError:  # FIXME: This is never thrown...
            logging.exception("")
            return None
        else:
            packet = Packet(packetList)
            if packet.valid:
                self.handlePacketHistory(packet)
            return packet

    def useByteQueue(self, useByteQueue = True):
        self.uart.useByteQueue = useByteQueue

    def getByteQueue(self):
        return self.uart.byteQueue

    def sendPacket(self, id, payload):
        packetList = [HEADER_LENGTH] + [len(payload)] + [PROTOVER_V1] + toLittleEndian(self.packetCounter, 2) + [id] + payload
        packetList = self.encodeToSLIP(packetList)
        self.packetCounter += 1
        self.uart.writeList(packetList)

    def sendScan(self):
        self.sendPacket(REQ_SCAN_CONT, [])

    def sendFollow(self, addr, txAdd=1, followOnlyAdvertisements = False):
        # TxAdd is a single byte (0 or 1) so we just append it to the address.
        self.sendPacket(REQ_FOLLOW, addr+[followOnlyAdvertisements])

    def sendPingReq(self):
        self.sendPacket(PING_REQ, [])

    def sendTK(self, TK):
        if (len(TK) < 16):
            TK = [0] * (16-len(TK)) + TK
        else:
            TK = TK[:16]
        self.sendPacket(SET_TEMPORARY_KEY, TK)

        logging.info("Sent key value to sniffer: "+str(TK))
        self.notify("TK_SENT", {"TK":TK})
        return TK

    def sendSwitchBaudRate(self, newBaudRate):
        self.sendPacket(SWITCH_BAUD_RATE_REQ, toLittleEndian(newBaudRate, 4))

    def switchBaudRate(self, newBaudRate):
        self.uart.switchBaudRate(newBaudRate)

    def sendHopSequence(self, hopSequence):
        for chan in hopSequence:
            if chan not in VALID_ADV_CHANS:
                raise Exceptions.InvalidAdvChannel("%s is not an adv channel" % str(chan))
        payload = [len(hopSequence)] + hopSequence + [37]*(3-len(hopSequence))
        self.sendPacket(SET_ADV_CHANNEL_HOP_SEQ, payload)
        self.notify("NEW_ADV_HOP_SEQ", {"hopSequence":hopSequence})

    def sendGoIdle(self):
        self.sendPacket(GO_IDLE, [])


class Packet:
    def __init__(self, packetList):
        try:
            if not packetList:
                raise Exceptions.InvalidPacketException("packet list not valid: %s" % str(packetList))

            self.protover = packetList[PROTOVER_POS]
            self.packetCounter = parseLittleEndian(packetList[PACKETCOUNTER_POS:PACKETCOUNTER_POS + 2])
            self.id = packetList[ID_POS]

            if int(self.protover) == PROTOVER_V1:
                self.payloadLength = packetList[PAYLOAD_LEN_POS_V1]
            elif int(self.protover) == PROTOVER_V2:
                self.payloadLength = parseLittleEndian(packetList[PAYLOAD_LEN_POS:PAYLOAD_LEN_POS + 2])
            else:
                raise RuntimeError("Unsupported protocol version %s" % str(self.protover))

            self.packetList = packetList
            self.readPayload(packetList)

        except Exceptions.InvalidPacketException as e:
            logging.error("Invalid packet: %s" % str(e))
            self.OK = False
            self.valid = False
        except:
            logging.exception("packet creation error")
            logging.info("packetList: " + str(packetList))
            self.OK = False
            self.valid = False

    def __repr__(self):
        return "UART packet, type: "+str(self.id)+", PC: "+str(self.packetCounter)

    def readPayload(self, packetList):
        self.blePacket = None
        self.OK = False

        if not self.validatePacketList(packetList):
            raise Exceptions.InvalidPacketException("packet list not valid: %s" % str(packetList))
        else:
            self.valid = True

        self.payload = packetList[PAYLOAD_POS:PAYLOAD_POS+self.payloadLength]

        if self.id == EVENT_PACKET:
            try:
                self.bleHeaderLength = packetList[BLE_HEADER_LEN_POS]
                if self.bleHeaderLength == BLE_HEADER_LENGTH:
                    self.flags = packetList[FLAGS_POS]
                    self.readFlags()
                    self.channel = packetList[CHANNEL_POS]
                    self.rawRSSI = packetList[RSSI_POS]
                    self.RSSI = -self.rawRSSI
                    self.txAdd = packetList[TXADD_POS] & TXADD_MSK
                    self.eventCounter = parseLittleEndian(packetList[EVENTCOUNTER_POS:EVENTCOUNTER_POS+2])
                    self.timestamp = parseLittleEndian(packetList[TIMESTAMP_POS:TIMESTAMP_POS+4])

                    # The hardware adds a padding byte which isn't sent on air.
                    # We remove it, and update the payload length in the packet list.
                    self.packetList.pop(BLEPACKET_POS+6)
                    self.payloadLength -= 1
                    if self.protover >= PROTOVER_V2:
                        # Write updated payload length back to the packet list.
                        payloadLength = toLittleEndian(self.payloadLength, 2)
                        packetList[PAYLOAD_LEN_POS  ] = payloadLength[0]
                        packetList[PAYLOAD_LEN_POS+1] = payloadLength[1]
                    else: # PROTOVER_V1
                        packetList[PAYLOAD_LEN_POS_V1] = self.payloadLength

                if self.OK:
                    try:
                        self.blePacket = BlePacket(packetList[BLEPACKET_POS:])
                    except:
                        logging.exception("blePacket error")
            except:
                # malformed packet
                logging.exception("packet error")
                self.OK = False
        elif self.id == PING_RESP:
            self.version = parseLittleEndian(self.packetList[PAYLOAD_POS:PAYLOAD_POS+2])
        elif self.id == SWITCH_BAUD_RATE_RESP or self.id == SWITCH_BAUD_RATE_REQ:
            self.baud_rate = parseLittleEndian(packetList[PAYLOAD_POS:PAYLOAD_POS+4])
        elif self.id == TEST_RESULT_ID:
            self.testId = packetList[PAYLOAD_POS]
            self.testLength = packetList[PAYLOAD_POS+1]
            self.testPayload = packetList[PAYLOAD_POS+2:]

    def readFlags(self):
        self.crcOK = not not (self.flags & 1)
        self.direction = not not (self.flags & 2)
        self.encrypted = not not (self.flags & 4)
        self.micOK = not not (self.flags & 8)
        self.phy = (self.flags >> 4) & 7
        self.OK = self.crcOK and (self.micOK or not self.encrypted)

    def getList(self):
        return self.packetList

    def validatePacketList(self, packetList):
        try:
            if (self.payloadLength + HEADER_LENGTH) == len(packetList):
                return True
            else:
                return False
        except:
            logging.exception("Invalid packet: %s" % str(packetList))
            return False

class BlePacket():
    def __init__(self, packetList):
        self.extractAccessAddress(packetList)
        if self.accessAddress == ADV_ACCESS_ADDRESS:    
            self.extractAdvType(packetList)
            # Mac address in decimal as a list
            self.extractAdvAddress(packetList)
            self.extractName(packetList)
        self.extractLength(packetList)
        self.payload = packetList[6:]
        self.customPayload = packetList # This gives me whole Low energy link layer
        
    def __repr__(self):
        #return "BLE packet, AAddr: "+ self.advAddressHuman  + " Payload : " + str(self.payload) 
        return ""
        
    def getPayload(self):
        return self.customPayload

    def extractAccessAddress(self, packetList):
        self.accessAddress = packetList[0:4]

    def extractAdvType(self, packetList):
        self.advType = (packetList[4] & 15)

    def extractAdvAddress(self, packetList):
        addr = None
        if (self.advType == 0 or self.advType == 1 or self.advType == 2 or self.advType == 4 or self.advType == 6):
            addrType = not not packetList[4]&64
            addr = packetList[6:12]
            addr.reverse()
            addr += [addrType]
        elif (self.advType == 3 or self.advType == 5):
            addrType = not not packetList[4]&64
            addr = packetList[12:18]
            addr.reverse()
            addr += [addrType]

        self.advAddress = addr
        self.extractAdvAddressHR()

    # Mac address in human readable form!
    def extractAdvAddressHR(self):
        
        #self.advAddressHuman = ""
        #for byte in self.advAddress:
        #    self.advAddressHuman = "{0}-{1}".format(self.advAddressHuman,
        #                                            "%02X" % byte)

        self.advAddressHuman = "{0}:{1}:{2}:{3}:{4}:{5}".format("%02X" % self.advAddress[0],
                                        "%02X" % self.advAddress[1],
                                        "%02X" % self.advAddress[2],
                                        "%02X" % self.advAddress[3],
                                        "%02X" % self.advAddress[4],
                                        "%02X" % self.advAddress[5])

    def extractName(self, packetList):
        name = ""
        if (self.advType == 0 or self.advType == 2 or self.advType == 4 or self.advType == 6):
            i = 12
            while i < len(packetList):
                length = packetList[i]
                if (i+length+1) > len(packetList) or length == 0:
                    break
                type = packetList[i+1]
                if type == 8 or type == 9:
                    nameList = packetList[i+2:i+length+1]
                    name = ""
                    for j in nameList:
                        name += chr(j)
                i += (length+1)
            name = '"'+name+'"'
        elif (self.advType == 1):
            name = "[ADV_DIRECT_IND]"

        self.name = name

    def extractLength(self, packetList):
        length = packetList[5]
        self.length = length

def parseLittleEndian(list):
    total = 0
    for i in range(len(list)):
        total+=(list[i] << (8*i))
    return total

def toLittleEndian(value, size):
    list = [0]*size
    for i in range(size):
        list[i] = (value >> (i*8)) % 256
    return list

