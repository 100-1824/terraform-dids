#!/usr/bin/env python3
import subprocess
import sys

# Tail Suricata’s JSON alert file and print each line to stdout
def main():
    # Make sure your suricata.yaml sends alerts to /var/log/suricata/eve.json
    cmd = ["tail", "-F", "/var/log/suricata/eve.json"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    for line in p.stdout:
        print(line.strip())
        sys.stdout.flush()

if __name__ == "__main__":
    main()

