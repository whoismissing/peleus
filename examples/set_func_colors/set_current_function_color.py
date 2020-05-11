"""
Set the listing background color of the function containing the currentAddr.

Useful to setup as a keybinding.
"""

import logging
import time
from java.awt import Color

from ghidra_util import log

# log obtained from 'ghidra_util.py'
log.setLevel(logging.DEBUG)

class FunctionColorizer():

    def __init__(self, func, color):
        log.info(func)
        self.func_obj = func
        self.color = color

    def colorize_addr(self, addr): 
        setBackgroundColor(addr, self.color)

    def colorize_addrs(self, addrs):
        monitor.initialize(10)
        for addr in addrs:
            monitor.checkCanceled()
            monitor.incrementProgress(1)
            monitor.setMessage("Working on: %s" % addr)
            self.colorize_addr(addr)

    def run(self):
        addr_set_view = self.func_obj.getBody() 
        addrs = addr_set_view.getAddresses(True)
        self.colorize_addrs(addrs)


def colorize_all_functions():
    funcs = currentProgram.getFunctionManager().getFunctions(True)
    [ FunctionColorizer(func, Color.CYAN).run() for func in funcs ]

def main():

    colorize_all_functions()

    """
    current_func = getFunctionContaining(currentAddress)
    if current_func is not None:
        colorizer = FunctionColorizer(current_func, Color.CYAN)
        colorizer.run()
    else:
        log.error('%s is not contained in a function' % currentAddress)
    """

main()
