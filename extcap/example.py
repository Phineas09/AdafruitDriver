import time
from SnifferAPI import Sniffer, UART

nPackets = 0
mySniffer = None

def setup():
    global mySniffer
    
    mySniffer = Sniffer.Sniffer("/dev/ttyUSB0")

    #if len(ports) > 0:
        # Initialize the sniffer on the first COM port found with baudrate 1000000.
        # If you are using an old firmware version <= 2.0.0, simply remove the baudrate parameter here.
        #mySniffer = Sniffer.Sniffer(portnum=ports[0])
    #    print("Found one device!")
    #else:
    #    print("No sniffers found!")
    #    return
    
    # Start the sniffer module. This call is mandatory.
    mySniffer.setAdvHopSequence([37, 38, 39])
    
    mySniffer.start()
    # Wait to allow the sniffer to discover device mySniffer.
    time.sleep(5)
    # Retrieve list of discovered devicemySniffer.
    # Find device with name "Example".

    d = None

    while d is None:
        print("Scanning for BLE devices (5s) ...")
        devlist = scanForDevices()
        if len(devlist):
            # Select a device
            d = selectDevice(devlist)
        print(devlist)

    mySniffer.follow(d)
    


def follow(sniffer, dev):
    sniffer.follow(dev)

def selectDevice(devlist):
    """
    Attempts to select a specific Device from the supplied DeviceList
    @param devlist: The full DeviceList that will be used to select a target Device from
    @type devlist: DeviceList
    @return: A Device object if a selection was made, otherwise None
    @rtype: Device
    """
    count = 0

    if len(devlist):
        print("Found {0} BLE devices:\n".format(str(len(devlist))))
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
    mySniffer.scan()
    time.sleep(scantime)
    devs = mySniffer.getDevices()
    return devs

def loop():
    # Enter main loop
    nLoops = 0
    while True:
        time.sleep(0.1)
        # Get (pop) unprocessed BLE packets.
        packets = mySniffer.getPackets()
        
        processPackets(packets) # function defined below
        
        nLoops += 1
        
        # print diagnostics every so often
        if nLoops % 20 == 0:
            print(mySniffer.getDevices())
            print("inConnection", mySniffer.inConnection)
            print("currentConnectRequest", mySniffer.currentConnectRequest)
            print("packetsInLastConnection", mySniffer.packetsInLastConnection)
            print("nPackets", nPackets)
            print()
        
# Takes list of packets
def processPackets(packets):
    for packet in packets:
        # packet is of type Packet
        # packet.blePacket is of type BlePacket
        if packet.blePacket != None:

            payload = packet.blePacket.getPayload()
            packetLen = len(payload)
            roundedLen = packetLen + (4 - packetLen % 4)
            for _ in range(packetLen, roundedLen):
                payload.append(0)

            for _ in payload:
                print("%02x " % _ ,end="")
            print("")

            print(len(payload))
            newFileByteArray = bytearray(packet.blePacket.getPayload())

        #newFile = open("file.bin", "wb", buffering=0)
        #print(newFile.write(newFileByteArray))

        #newFile.close()
            global nPackets
        # if packet.OK:
        # Counts number of packets which are not malformed.
            nPackets += 1
    
setup()
if mySniffer is not None:
    loop()

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