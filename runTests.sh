#python3 testArguments.py -store -out test -n 100

echo "Only on processor"
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test100.sniff -n 100
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test200.sniff -n 200
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test400.sniff -n 400
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test800.sniff -n 800

echo "With coprocessor"
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test100.sniff -n 100 --FPGA
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test200.sniff -n 200 --FPGA
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test400.sniff -n 400 --FPGA
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test800.sniff -n 800 --FPGA

echo "With coprocessor threaded"
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test100.sniff -n 100 --FPGA --threaded
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test200.sniff -n 200 --FPGA --threaded
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test400.sniff -n 400 --FPGA --threaded
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test800.sniff -n 800 --FPGA --threaded

# Examples
python3 testArguments.py -captureFile test --FPGA --threaded
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test100.sniff -n 100 --FPGA --threaded

Known devices   
Device-d9:be:75:1d:26:a8-23:53:24:04/07/2021
