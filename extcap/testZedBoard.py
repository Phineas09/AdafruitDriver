
import argparse
import re
import os
import enum
import time

# [217, 190, 117, 29, 38, 168, 0, 0] = d9:be:75:1d:26:a8

newFile = open("/dev/xillybus_write_32", "wb",buffering=0)
file2 =  open("/dev/xillybus_read_32", "rb")
newFileByteArray = bytearray([0x00, 0x00,0x00,0x00] + [217, 190, 117, 29, 38, 168, 0, 0])
print(newFile.write(newFileByteArray))


print(int.from_bytes(file2.read(4), byteorder='little', signed=True)) #This should be 0
print(int.from_bytes(file2.read(4), byteorder='little', signed=True)) #This should be 0
start_time = time.perf_counter()
newFileByteArray = bytearray([0x01, 0x00,0x00,0x00] + [0x20, 0x25, 0xa8, 0x26, 0x1d, 0x75, 0xbe, 0xd9])
print(newFile.write(newFileByteArray))

print(int.from_bytes(file2.read(4), byteorder='little', signed=True)) #This should be 0
print(int.from_bytes(file2.read(4), byteorder='little', signed=True)) #This should be 0
stop_time = time.perf_counter()
print((stop_time - start_time)* 1000) # In ms