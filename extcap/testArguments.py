import argparse
import re
import os
import enum
import time
import threading
from datetime import datetime


from SnifferAPI import Sniffer, UART

nPackets = 0
mySniffer = None

readingThread = None
numberOfStoredPackets = 0

zedBoard = False
setupDone = False

executionTimeInSeconds = 0

packetList = []

## Macros for usage mode

class OperatingMode(enum.Enum):
    Online = 0
    Offline = 1
    Store = 2
    Detect = 3

snifferParser = argparse.ArgumentParser(prog='Sniffer', description='Sniffer for BLE communications. Online mode is on by default.')

snifferParser.version = '1.0'
snifferParser.add_argument('-logFile', action='store', help='Custom log file for logging events.')

snifferParser.add_argument('-captureFile', action='store', help='Capture file to save packets in online mode. Default is capture_<date>.sniff')

snifferParser.add_argument('-mac', action='store', help='Bluetooth MAC addres to filter packets by.')
snifferParser.add_argument('-offline', action='store_true', help="Filter all packets in a given capture, needs a mac address and an input file.")
snifferParser.add_argument('-inFile', action='store', help='Capture file load packets in offline mode. This file must be a .sniff file')
#Offline mode will display on the screen and into some random file

snifferParser.add_argument('-store', action='store_true', help='Store all detected packets in given file.')
snifferParser.add_argument('-n', action='store', type=int, help='Number of packets to store, default 200.', default=200)
snifferParser.add_argument('-out', action='store', help='Used for storing output of -store and -offline functions.') 

snifferParser.add_argument('-detect', action='store_true', help='Detect new nearby devices.')
#snifferParser.add_argument('-detectFile', action='store', help='File from keeping track of new devices. \
#                            detectedDevs.log will be used as default.', default="detectedDevs.log")

snifferParser.add_argument('--FPGA', action='store_true', help="Run the filters on the programmable logic.")
snifferParser.add_argument('--threaded', action='store_true', help="Run the filters on the programmable logic.")

snifferParser.add_argument('-v', action='version', help='Show program version and exit.')


def configureLogFile(args):
    try:
        if args.logFile == None:
            args.logFile=("./logFiles/log_" + datetime.now().strftime("%Y%m%d" + ".log")

        if os.path.exists(args.logFile):
            append_write = 'a' # append if already exists
        else:
            append_write = 'w' # make a new file if not
        loggerFile = open(args.logFile, append_write)
        args.loggerFile = loggerFile
        return loggerFile
    except Exception:
        return None

def logMessage(loggerFile, message):
    message = datetime.now().strftime("%H:%M:%S:%d/%m/%Y ") + message + "\n"
    loggerFile.write(message)



def verifyMacAddress(args):
    if args.mac != None:
        if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.mac.lower()):
            args.macAddressList = [] 
            splitMacAddress = args.mac.split(':')
            for _ in splitMacAddress:
                args.macAddressList.append(int(_, 16))
            #print(args.macAddressList)
            return True
    print("You must specify a valid MAC Address using \'-mac!\'")
    return False


def verifyFileExists(fileName, option = "\'-inFile\'"):
    if fileName == None:
        print("You must specify a valid input file using " + option)
        return False
    if os.path.exists(fileName):
        extension = os.path.splitext(fileName)[1]
        if extension == ".sniff":
            """
            try:
                loggerFile = open(fileName, "rb")
                args.loggerFile = loggerFile
            except Exception:
                print("Could not open specified input file! (" + fileName + ")")
                return False            
            """
            return True
        else:
            print("You must provide a .sniff file")
            return False
    else:
        print("Provided file does not exits in your sistem!")
    return False



def parseArguments(args) -> OperatingMode:

    ## Operating modes

    # Online packets analysis
    # Offline packet analysis
    # Detect new nearby devices
    # Store packets into file, specify number of packets to store, default 200?

    global zedBoard
    zedBoard = args.FPGA

    args.loggerFile = configureLogFile(args)

    if args.offline:
        if verifyMacAddress(args):
            if verifyFileExists(args.inFile):
                if args.out != None:
                    args.out = args.out + ".sniff"
                else:
                    args.out = ("./out/offlineFiltering_" + datetime.now().strftime("%Y%m%d:%H:%M:%S") + ".sniff")
                args.storeFile = open(args.out, "wb")
                # We have all we need
                return OperatingMode.Offline
    
    if args.store:
        #File where to store 
        if args.out != None:
            args.out = args.out + ".sniff"
            args.storeFile = open(args.out, "wb")
            return OperatingMode.Store
        else:
            print("You must provide an output file using \'-out\'!")
    if args.detect == True:
        return OperatingMode.Detect

    return OperatingMode.Online
    

def setup():
    global mySniffer
    mySniffer = Sniffer.Sniffer("/dev/ttyUSB0")
    mySniffer.setAdvHopSequence([37, 38, 39])
    mySniffer.start()
    time.sleep(5)


# Takes list of packets
def storePackets(packets, args):
    for packet in packets:
        if packet.blePacket != None:
            payload = packet.blePacket.getPayload()
            packetLen = len(payload)
            roundedLen = packetLen + (4 - packetLen % 4)
            for _ in range(packetLen, roundedLen):
                payload.append(0)
            payload.insert(0, roundedLen)
            #print(roundedLen)
            args.storeFile.write(bytearray(payload))
            global nPackets
            nPackets += 1
            if nPackets >= args.n:
                return

def storePacket(payload, args):
    packetLen = len(payload)
    args.storeFile.write(bytearray([packetLen]))
    print(packetLen, payload)
    args.storeFile.write(payload)
    logMessage(args.loggerFile, "Stored matching packet in " + args.out)


def loopStore(args):
    global nPackets
    while nPackets < args.n:
        time.sleep(0.1)
        packets = mySniffer.getPackets()
        storePackets(packets, args) #Function to store the packets
    args.storeFile.close()



def selectDeviceForFollowing():
    d = None

    while d is None:
        print("Scanning for BLE devices (5s) ...")
        devlist = scanForDevices()
        if len(devlist):
            # Select a device
            d = selectDevice(devlist)
        print(devlist)

    mySniffer.follow(d)


def setupFpgaMac(args):
    
    # Mac in args.macAddressList 
    #newFileBytes = [0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x03]
    args.fpgaIn = open("/dev/xillybus_write_32", "wb", buffering=0)
    args.fpgaOut = open("/dev/xillybus_read_32", "rb", buffering=0)
    newFileByteArray = bytearray([0x00, 0x00,0x00,0x00] + args.macAddressList + [0, 0]) # Packet id + mac + padding
    args.fpgaIn.write(newFileByteArray)

    if (int.from_bytes(args.fpgaOut.read(4), byteorder='little', signed=True)) == 0:
        global setupDone
        setupDone = True


def processPackets(packetLen, packetBytes, args):
    global executionTimeInSeconds
    #start_time = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    start_time = time.perf_counter()
    if zedBoard:
        if setupDone == False:
            #Make setup
            #print("Make setup")
            setupFpgaMac(args)
            if args.threaded == True:
                global readingThread
                readingThread = threading.Thread(target=readFPGAResponse, args=(args,))
                readingThread.start()

        processPacketsOnCoprocessor(packetLen, packetBytes, args)
    else:
        processPacketsProcessor(packetLen, packetBytes, args)
    #stop_time = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    stop_time = time.perf_counter()
    #executionTimeInSeconds += (stop_time - start_time)/1000000
    executionTimeInSeconds += (stop_time - start_time) # * 1000
    

def readFPGAResponse(args):

    nrPackets = 0
    global packetList
    global numberOfStoredPackets

    while nrPackets < args.n:

        packetStatus = int.from_bytes(args.fpgaOut.read(4), byteorder='little', signed=True)

        #if packetStatus == 1:
            #Error

        if packetStatus == 2 or packetStatus == 0:
            storePacket(packetList.pop(0), args)
            numberOfStoredPackets += 1

        nrPackets += 1
    print("Am filtrat ", end="")
    print(nrPackets) # Remove 
    args.fpgaOut.close()
    return


def printPacketHex(packetLen, packetBytes):
    for i in range(0, packetLen):
        print("%02x " % packetBytes[i], end="")
    print("")


def processPacketsProcessor(packetLen, packetBytes, args):

    # Mac in args.macAddressList
    global numberOfStoredPackets
    #printPacketHex(packetLen, packetBytes)
    if packetLen > 12:
        if packetBytes[6] == args.macAddressList[5] and \
            packetBytes[7] == args.macAddressList[4] and \
            packetBytes[8] == args.macAddressList[3] and \
            packetBytes[9] == args.macAddressList[2] and \
            packetBytes[10] == args.macAddressList[1] and \
            packetBytes[11] == args.macAddressList[0]:
            
            numberOfStoredPackets += 1
            storePacket(packetBytes, args)
            # Do stuff with it
            #printPacketHex(packetLen, packetBytes)
            #print("Matching")

            #print them to args.storeFile // Here

            return
    return



def processPacketsOnCoprocessor(packetLen, packetBytes, args):


    localList = []
    for i in range(4,12):
        localList.append(packetBytes[i])
    args.fpgaIn.write(bytearray(localList))
    if args.threaded == False:
        packetStatus = int.from_bytes(args.fpgaOut.read(4), byteorder='little', signed=True)


        #if packetStatus == 1:
            #Error
        #    print("Not interesting")
        #if packetStatus == 2:
        #    print("Att packet")

        #if packetStatus == 0:
        #    print("Advertising")
    # Mac in args.macAddressList

    '''
    newFileBytes = [0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x03]
    # make file
    newFile = open("/dev/xillybus_write_32", "wb",buffering=0)
    file2 =  open("/dev/xillybus_read_32", "rb")
    # write to file
    print(newFile)
    print(file2)
    newFileByteArray = bytearray(newFileBytes)
    print(newFile.write(newFileByteArray))

    print(int.from_bytes(file2.read(4), byteorder='little', signed=True))
    print(int.from_bytes(file2.read(4), byteorder='little', signed=True))

    '''
    return

#args.inFile
def processOfflinePackets(args):

    args.offlinePacketsFile = open(args.inFile, "rb")
    packetLen = int.from_bytes(args.offlinePacketsFile.read(1), "little")
    global packetList
    processedPackets = 0
    while packetLen != 0:

        if (processedPackets % 128) == 0:
            time.sleep(0.05)   

        packetBytes = args.offlinePacketsFile.read(packetLen)
        packetList.append(packetBytes)

        processPackets(packetLen, packetBytes, args)

        packetLen = int.from_bytes(args.offlinePacketsFile.read(1), "little")
        # Send to processing (packetLen, bytes)
        processedPackets += 1

    args.offlinePacketsFile.close()

    global zedBoard
    if zedBoard == True:
        args.fpgaIn.close()
        if args.threaded == False:
            args.fpgaOut.close()

    global numberOfStoredPackets


    print("Processed %d packets." % processedPackets)
    print(numberOfStoredPackets)
    return


def main():
    args = snifferParser.parse_args()
    global executionTimeInSeconds

    #Interpret arguments, then switch for according usage

    selectedOperatingMode = parseArguments(args)


    if type(selectedOperatingMode) == OperatingMode:
        if selectedOperatingMode == OperatingMode.Online: #Operating mode

            pass
            logMessage(args.loggerFile, "Program opened in online mode")
            print("Online mode!")

        if selectedOperatingMode == OperatingMode.Offline: #Operating mode

            #Mac will be in args.macAddressList

            logMessage(args.loggerFile, "Program opened in offline mode")

            processOfflinePackets(args)


            if args.threaded == True:
                global readingThread
                readingThread.join()

            args.storeFile.close()
            #print("Offline mode!")
        if selectedOperatingMode == OperatingMode.Store: #Operating mode
            logMessage(args.loggerFile, "Program opened in store mode")

            #print("Store mode!")
            setup()
            # Store in args.out
            loopStore(args)

        if selectedOperatingMode == OperatingMode.Detect: #Operating mode

            logMessage(args.loggerFile, "Program opened in detection mode")

            print("Detect mode!")
    else:
        print("Fatal error!")

    #if configureLogFile(args) != None:
    
    try:
        #loggerFile = configureLogFile(args)

        print("Processing time %s seconds" % executionTimeInSeconds) 

    except IOError:
        input("Could not open file! Please close Excel. Press Enter to retry.")


if __name__ == "__main__":
    main()
