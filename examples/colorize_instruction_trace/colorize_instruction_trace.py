"""
Colorize the disassembly listing given a trace file of instruction pointers
"""

import logging
import time
from java.awt import Color

from ghidra_util import log

# log obtained from 'ghidra_util.py'
log.setLevel(logging.DEBUG)

def read_trace_file(trace_file):
    with open(trace_file, 'r') as fd:
        return fd.read()


class InstructionTraceColorizer():

    def __init__(self):
        self.trace_file = None

    def colorize_instruction(self, addr): 
        log.info(addr)
        setBackgroundColor(addr, Color.CYAN)

    def colorize_instructions(self, addrs):
        # Report progress to the GUI.  Do this in all script loops!
        # from examples/ghidra_basics.py
        monitor.initialize(10)
        for addr in addrs:

            # Check to see if the user clicked cancel
            monitor.checkCanceled()
            #time.sleep(1) # Pause to see progress
            #monitor.incrementProgress(1) # Update the progress
            monitor.setMessage("Working on: %s" % addr) # Update status message

            try:
                addr_obj = parseAddress(addr)
            except:
                log.error('IllegalArgumentException: Invalid address')

            self.colorize_instruction(addr_obj)

    def trace_instructions(self, trace_file):
        file_path = trace_file.getAbsolutePath()
        addrs = read_trace_file(file_path).split('\n')
        self.colorize_instructions(addrs)


def main():

    trace_file = askFile("FILE", "Select a trace file:")

    colorizer = InstructionTraceColorizer()
    colorizer.trace_instructions(trace_file)

main()
