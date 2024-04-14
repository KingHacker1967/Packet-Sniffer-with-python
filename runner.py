import subprocess
import time

pcap_script = subprocess.Popen(['python', '../sniffer.py'])

time.sleep(10)

zeek_script = subprocess.Popen(['zeek', '-C', '-r', '../capture.pcap', '../script.zeek'])

while pcap_script.poll() is None:
    time.sleep(1)

zeek_script.terminate()