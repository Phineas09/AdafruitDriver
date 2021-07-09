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