import argparse
import re
import os
import enum
import time
from datetime import datetime


from SnifferAPI import Sniffer, UART

nPackets = 0
mySniffer = None

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
snifferParser.add_argument('-offline', action='store_true')
snifferParser.add_argument('-inFile', action='store', help='Capture file load packets in offline mode. This file must be a .sniff file')
#Offline mode will display on the screen and into some random file

snifferParser.add_argument('-store', action='store_true', help='Store all detected packets in given file.')
snifferParser.add_argument('-n', action='store', type=int, help='Number of packets to store, default 200.', default=200)
snifferParser.add_argument('-out', action='store', help='Used for storing output of -store function.') 

snifferParser.add_argument('-detect', action='store_true', help='Detect new nearby devices.')
#snifferParser.add_argument('-detectFile', action='store', help='File from keeping track of new devices. \
#                            detectedDevs.log will be used as default.', default="detectedDevs.log")

snifferParser.add_argument('-v', action='version', help='Show program version and exit.')


def configureLogFile(args):
    try:
        if args.logFile == None:
            args.logFile=("./logFiles/log_" + datetime.now().strftime("%Y%m%d"))

        if os.path.exists(args.logFile):
            append_write = 'a' # append if already exists
        else:
            append_write = 'w' # make a new file if not
        loggerFile = open(args.logFile, append_write)
        args.loggerFile = loggerFile
        return loggerFile
    except Exception:
        return None



def verifyMacAddress(args):
    if args.mac != None:
        if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.mac.lower()):
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

    if args.offline:
        if verifyMacAddress(args):
            if verifyFileExists(args.inFile):
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

    return None
    

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
            print(roundedLen)
            args.storeFile.write(bytearray(payload))
            global nPackets
            nPackets += 1
            if nPackets >= args.n:
                return


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

def processPacketsProcessor(packetLen, packetBytes):

    for i in range(0, packetLen):
        print("%02x " % packetBytes[i], end="")
    print("")

    return

def processPacketsOnCoprocessor(packetLen, packetBytes):

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
    pass

#args.inFile
def processOfflinePackets(args):

    args.offlinePacketsFile = open(args.inFile, "rb")
    packetLen = int.from_bytes(args.offlinePacketsFile.read(1), "little")

    while packetLen != 0:
        packetBytes = args.offlinePacketsFile.read(packetLen)

        print(packetBytes)
        
        processPacketsProcessor(packetLen, packetBytes)

        packetLen = int.from_bytes(args.offlinePacketsFile.read(1), "little")
        # Send to processing (packetLen, bytes)


    args.offlinePacketsFile.close()
    
    return


def main():
    args = snifferParser.parse_args()

    #Interpret arguments, then switch for according usage

    testVar = parseArguments(args)

    if type(testVar) == OperatingMode:
        if testVar == OperatingMode.Online: #Operating mode

            print("Online mode!")

        if testVar == OperatingMode.Offline: #Operating mode

            processOfflinePackets(args)

            print("Offline mode!")
        if testVar == OperatingMode.Store: #Operating mode
            print("Store mode!")
            setup()
            # Store in args.out
            loopStore(args)
        if testVar == OperatingMode.Detect: #Operating mode


            print("Detect mode!")
    else:
        print("Error")

    #if configureLogFile(args) != None:
    
    try:
        #loggerFile = configureLogFile(args)


                
        print(vars(args))
    except IOError:
        input("Could not open file! Please close Excel. Press Enter to retry.")
        # restart the loop


if __name__ == "__main__":
    main()
