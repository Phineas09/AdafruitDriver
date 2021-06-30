#python3 testArguments.py -store -out test -n 100

python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test100.sniff -n 100
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test200.sniff -n 200
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test400.sniff -n 400
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test800.sniff -n 800

python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test100.sniff -n 100 --FPGA
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test200.sniff -n 200 --FPGA
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test400.sniff -n 400 --FPGA
python3 testArguments.py -offline -mac d9:be:75:1d:26:a8 -inFile ./utils/test800.sniff -n 800 --FPGA
