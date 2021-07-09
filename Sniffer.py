import argparse
import re
import os
import enum
import time
import threading
from datetime import datetime


'''
python3 Sniffer.py -captureFile test --FPGA --threaded
python3 Sniffer.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test100.sniff -n 100 --FPGA --threaded
python3 Sniffer.py -detect

'''

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
snifferParser.add_argument('-whiteList', action='store', help='Provided whitelist for detection of unknown devices. List must be Device-<MAC ADDRESS>')


snifferParser.add_argument('--FPGA', action='store_true', help="Run the filters on the programmable logic.")
snifferParser.add_argument('--threaded', action='store_true', help="Run the filters on the programmable logic.")

snifferParser.add_argument('-v', action='version', help='Show program version and exit.')


def configureLogFile(args):
    try:
        if args.logFile == None:
            args.logFile=("./logFiles/log_" + datetime.now().strftime("%Y%m%d" + ".log"))

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
    loggerFile.flush()



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
        
        # Have a statis file to read the devices from, if exists open in append, else
        # create it and read all of it's contents
        # scan every 15 seconds an notify if there is a new device


        if args.whiteList == None:
            args.whiteList = "knownDevices"         

        if os.path.exists(args.whiteList):
            with open(args.whiteList) as f:
                content = f.readlines()
            content = [x.strip() for x in content]
            args.knownDevices = {}  
            for _ in content:
                key = _.split("-")[1]
                if key not in args.knownDevices:
                    args.knownDevices[key] = 1
        else:
            return None
                #Open file and read it's contents, else error
        
        return OperatingMode.Detect

    #Meaning we are in OnlineMode

    if args.captureFile != None:
        args.captureFile = args.captureFile + ".sniff"
    else:
        args.captureFile = ("./out/onlineFiltering_" + datetime.now().strftime("%Y%m%d:%H:%M:%S") + ".sniff")
    
    args.out = args.captureFile
    args.storeFile = open(args.captureFile, "wb")    

    # Maybe see something about the mac address?

    return OperatingMode.Online
    

def setup(args):
    global mySniffer
    mySniffer = Sniffer.Sniffer("/dev/ttyUSB0")
    mySniffer.setAdvHopSequence([37, 38, 39])
    mySniffer.start()
    logMessage(args.loggerFile, "Initializing device /dev/ttyUSB0")
    print("Scanning for BLE devices (5s) ...")
    logMessage(args.loggerFile, "Scanning for BLE devices (5s) ...")
    time.sleep(5)


def selectDevice(devlist, args):
    count = 0

    if len(devlist):
        print("Found {0} BLE devices:\n".format(str(len(devlist))))
        logMessage(args.loggerFile, "Found %d BLE devices!" % len(devlist))

        # Display a list of devices, sorting them by index number
        for d in devlist.asList():
            """@type : Device"""
            count += 1
            print("  [{0}] {1} ({2}:{3}:{4}:{5}:{6}:{7}, RSSI = {8})".format(count, d.name,
                                                                             "%02X" % d.address[0],
                                                                             "%02X" % d.address[1],
                                                                             "%02X" % d.address[2],
                                                                             "%02X" % d.address[3],
                                                                             "%02X" % d.address[4],
                                                                             "%02X" % d.address[5],
                                                                             d.RSSI))
        try:
            i = int(input("\nSelect a device to sniff, or '0' to scan again\n> "))
        except KeyboardInterrupt:
            print("\nProgram stopped!")

            exit(1)
            #raise KeyboardInterrupt
            return None
        except:
            return None

        # Select a device or scan again, depending on the input
        if (i > 0) and (i <= count):
            # Select the indicated device
            return devlist.find(i - 1)
        else:
            # This will start a new scan
            return None

def scanForDevices(scantime=5):
    global mySniffer
    mySniffer.scan()
    time.sleep(scantime)
    devs = mySniffer.getDevices()
    return devs

def selectDeviceForFollowing(args):
    d = None

    while d is None:
        devlist = scanForDevices()
        if len(devlist):
            # Select a device
            d = selectDevice(devlist, args)
        #print(devlist)
    
    # Get device mac addres to follow and setup 

    # Here we need to configure args.macAddressList
    
    args.mac = "{0}:{1}:{2}:{3}:{4}:{5}".format("%02X" % d.address[0],
                                                "%02X" % d.address[1],
                                                "%02X" % d.address[2],
                                                "%02X" % d.address[3],
                                                "%02X" % d.address[4],
                                                "%02X" % d.address[5])
    verifyMacAddress(args)
    logMessage(args.loggerFile, "Selected device %s" % args.mac )

    logMessage(args.loggerFile, "Started following %s" % args.mac)

    mySniffer.follow(d)


def processOnlinePackets(packets, args):
    global packetList
    global nPackets
    global zedBoard
    for packet in packets:
        if packet.blePacket != None:

            payload = packet.blePacket.getPayload()
            packetLen = len(payload)

            payloadByteArray = bytearray(payload)
            if zedBoard and args.threaded:
                packetList.append(payloadByteArray)
        
            processPackets(packetLen, payloadByteArray, args, True)
            
            nPackets += 1
            if nPackets >= args.n:
                return
                

def loopOnlineFilter(args):
    global nPackets
    global mySniffer
    global numberOfStoredPackets

    #print(args.mac)
    #print(args.macAddressList)
    try:
        while True:
            time.sleep(0.1)
            packets = mySniffer.getPackets()
            processOnlinePackets(packets, args)
    except:   
        time.sleep(0.1)
        print("Captured %d packets and stored %d" % (nPackets, numberOfStoredPackets))
        logMessage(args.loggerFile, "Captured %d packets and stored %d" % (nPackets, numberOfStoredPackets))
        args.storeFile.close()

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
            print("Stored packet from: {0}:{1}:{2}:{3}:{4}:{5}".format("%02X" % payload[11],"%02X" % payload[10],"%02X" % payload[9],"%02X" % payload[8],"%02X" % payload[7],
            "%02X" % payload[6]))
            global nPackets
            nPackets += 1
            if nPackets >= args.n:
                return

def storePacket(payload, args):
    packetLen = len(payload)
    args.storeFile.write(bytearray([packetLen]))
    args.storeFile.write(payload)
    logMessage(args.loggerFile, "Stored matching packet in \"" + args.out + "\"")



def loopStore(args):
    global nPackets
    global mySniffer
    while nPackets < args.n:
        time.sleep(0.1)
        packets = mySniffer.getPackets()
        storePackets(packets, args) #Function to store the packets
    logMessage(args.loggerFile, "Stored %d packets!" % args.n)
    args.storeFile.close()


def setupFpgaMac(args):
    
    # Mac in args.macAddressList 
    #newFileBytes = [0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x03]
    args.fpgaIn = open("/dev/xillybus_write_32", "wb", buffering=0)
    args.fpgaOut = open("/dev/xillybus_read_32", "rb", buffering=0)
    newFileByteArray = bytearray([0x00, 0x00,0x00,0x00] + args.macAddressList + [0, 0]) 
    args.fpgaIn.write(newFileByteArray)

    if (int.from_bytes(args.fpgaOut.read(4), byteorder='little', signed=True)) == 0:
        global setupDone
        setupDone = True


def processPackets(packetLen, packetBytes, args, online = False):
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
                readingThread = threading.Thread(target=readFPGAResponse, args=(args,online))
                readingThread.daemon = True
                readingThread.start()

        processPacketsOnCoprocessor(packetLen, packetBytes, args)
    else:
        processPacketsProcessor(packetLen, packetBytes, args)
    #stop_time = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    stop_time = time.perf_counter()
    #executionTimeInSeconds += (stop_time - start_time)/1000000
    executionTimeInSeconds += (stop_time - start_time) # * 1000
    

def readFPGAResponse(args, online=False):
    try:
        nrPackets = 0
        global packetList
        global numberOfStoredPackets

        if online == False:
            while nrPackets < args.n:

                packetStatus = int.from_bytes(args.fpgaOut.read(4), byteorder='little', signed=True)

                if packetStatus == 1:
                    packetList.pop(0)

                if packetStatus == 2 or packetStatus == 0:
                    payload = packetList.pop(0)
                    storePacket(payload, args)
                    print("Packet Stored: Address [{0}:{1}:{2}:{3}:{4}:{5}]".format("%02X" % payload[11],
                                                "%02X" % payload[10],
                                                "%02X" % payload[9],
                                                "%02X" % payload[8],
                                                "%02X" % payload[7],
                                                "%02X" % payload[6]))
                    numberOfStoredPackets += 1
                    if packetStatus == 2:
                        print("Captured ATT packet %d" % nrPackets)

                nrPackets += 1
        else:
            while True:
                packetStatus = int.from_bytes(args.fpgaOut.read(4), byteorder='little', signed=True)

                if packetStatus == 1:
                    packetList.pop(0)

                if packetStatus == 2 or packetStatus == 0:
                    payload = packetList.pop(0)
                    storePacket(payload, args)
                    print("Packet Stored: Address [{0}:{1}:{2}:{3}:{4}:{5}]".format("%02X" % payload[11],
                                                "%02X" % payload[10],
                                                "%02X" % payload[9],
                                                "%02X" % payload[8],
                                                "%02X" % payload[7],
                                                "%02X" % payload[6]))

                    if packetStatus == 2:
                        print("Captured ATT packet %d" % nrPackets)
                    
                    numberOfStoredPackets += 1

                nrPackets += 1
        print("Filtered %d packets " % nrPackets, end="")
        #print(nrPackets) # Remove 
    except Exception:
        return
    finally:
        args.fpgaOut.close()
        return
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
            print("Packet Stored: Address [{0}:{1}:{2}:{3}:{4}:{5}]".format("%02X" % packetBytes[11],
                            "%02X" % packetBytes[10],
                            "%02X" % packetBytes[9],
                            "%02X" % packetBytes[8],
                            "%02X" % packetBytes[7],
                            "%02X" % packetBytes[6]))


            return
    return


def processPacketsOnCoprocessor(packetLen, packetBytes, args):

    localList = []
    global numberOfStoredPackets
    for i in range(4,12):
        localList.append(packetBytes[i])
    args.fpgaIn.write(bytearray(localList))

    if args.threaded == False:
        packetStatus = int.from_bytes(args.fpgaOut.read(4), byteorder='little', signed=True)
        
        if packetStatus == 2 or packetStatus == 0:
            storePacket(packetBytes, args)
            numberOfStoredPackets += 1

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
    global zedBoard
    processedPackets = 0
    while packetLen != 0:

        if (processedPackets % 128) == 0:
            time.sleep(0.05)   

        packetBytes = args.offlinePacketsFile.read(packetLen)

        if zedBoard and args.threaded:
            packetList.append(packetBytes)

        processPackets(packetLen, packetBytes, args)

        packetLen = int.from_bytes(args.offlinePacketsFile.read(1), "little")
        # Send to processing (packetLen, bytes)
        processedPackets += 1

    args.offlinePacketsFile.close()


    if zedBoard == True:
        args.fpgaIn.close()
        if args.threaded == False:
            args.fpgaOut.close()

    global numberOfStoredPackets

    logMessage(args.loggerFile, "Processed %d packets and stored %d." % (processedPackets, numberOfStoredPackets))
    return


def main():
    args = snifferParser.parse_args()

    #Interpret arguments, then switch for according usage

    selectedOperatingMode = parseArguments(args)


    if type(selectedOperatingMode) == OperatingMode:
        if selectedOperatingMode == OperatingMode.Online: #Operating mode

            try:
                logMessage(args.loggerFile, "Program opened in online mode")
                setup(args)
                selectDeviceForFollowing(args)

                loopOnlineFilter(args)

            except Exception:
                print("Something went wrong, aborting!")
                exit(0)

        if selectedOperatingMode == OperatingMode.Offline: #Operating mode

            #Mac will be in args.macAddressList

            logMessage(args.loggerFile, "Program opened in offline mode filter for (%s)" % args.mac)

            processOfflinePackets(args)

            if args.threaded == True:
                global readingThread
                readingThread.join()

            args.storeFile.close()
            args.loggerFile.close()
            print("Processing time %s seconds" % executionTimeInSeconds) 

        if selectedOperatingMode == OperatingMode.Store: #Operating mode
            logMessage(args.loggerFile, "Program opened in store mode in file \"%s\"" % args.out)
            setup(args)
            loopStore(args)
            args.loggerFile.close()

        if selectedOperatingMode == OperatingMode.Detect: #Operating mode

            logMessage(args.loggerFile, "Program opened in detection mode")
            
            try:
                setup(args)  
                while True:
                    newDevices = scanForDevices().asList()   

                    for d in newDevices:
                        foundMacAddress = "{0}:{1}:{2}:{3}:{4}:{5}".format("%02X" % d.address[0],
                                                    "%02X" % d.address[1],
                                                    "%02X" % d.address[2],
                                                    "%02X" % d.address[3],
                                                    "%02X" % d.address[4],
                                                    "%02X" % d.address[5]) 
                        if foundMacAddress not in args.knownDevices:
                            args.knownDevices[foundMacAddress] = 1   
                            logMessage(args.loggerFile, "Detected new device %s" % foundMacAddress)              
                            print("Detected new device %s" % foundMacAddress)
            except KeyboardInterrupt:
                print("Keyboard Interrupted")

    else:
        print("Fatal error!")
    try:
        if args.threaded == True:
            #global readingThread
            readingThread.stop()
            readingThread.join()

    except IOError:
        input("Could not open file!")
    except Exception:
        exit(0)

if __name__ == "__main__":
    main()
