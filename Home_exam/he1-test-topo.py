#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import os
import time

# Adjust these if your binary names differ
DAEMON = "mip_daemon"   # change to "mipd" if you rename later
PING_SRV = "ping_server"
PING_CLI = "ping_client"

# UNIX socket paths for A and B
SOCK_A = "/tmp/mip_A.sock"
SOCK_B = "/tmp/mip_B.sock"

class He1Topo(Topo):
    def build(self):
        A = self.addHost('A')
        B = self.addHost('B')
        self.addLink(A, B, bw=10, delay='10ms', loss=0)  # simple A—B

topos = {'he1-test': (lambda: He1Topo())}

def run():
    # Build once (assumes Makefile in current working dir)
    info("*** make clean && make\n")
    assert os.system("make clean >/dev/null 2>&1; make") == 0, "Build failed"

    topo = He1Topo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.start()

    A, B = net.get('A'), net.get('B')

    # Clean stale UNIX sockets
    A.cmd(f"rm -f {SOCK_A}")
    B.cmd(f"rm -f {SOCK_B}")

    # Choose MIP addresses
    mipA, mipB = 1, 2

    # Launch daemons (with -d for debug) directly in the background
    A.cmd(f"./{DAEMON} -d {SOCK_A} {mipA} &")
    B.cmd(f"./{DAEMON} -d {SOCK_B} {mipB} &")

    # Give them a moment to create their UNIX sockets
    time.sleep(0.5)

    # Start ping server on B
    B.cmd(f"./{PING_SRV} {SOCK_B} &")

    # Example: run one ping from A->B
    A.cmd(f"./{PING_CLI} {SOCK_A} {mipB} 'hello-from-A'")

    info("*** Ready. Use the CLI to run more tests.\n")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    run()
