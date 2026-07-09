import sys
import subprocess

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("usage: feature_read.py <netflow_path> <pcap_path> \n")
        sys.exit(1)

    netflow_path = sys.argv[1]
    pcap_path = sys.argv[2]
    # print(netflow_path)
    # print(pcap_path)

    # CLI test
    res = subprocess.run([netflow_path, "--read", pcap_path], capture_output=True, text=True)
    if res.returncode == 1 and "pcap_open_offline() failed" in res.stdout:
        print("PASS: feature_read miss.pcap passed")
        exit(0)
    else:
        print(res.returncode)
        print(res.stdout)
        print(res.stderr)
        exit(1)


