"""
Common utility functions for use across ghidra scripts
"""

"""
Only the script that gets directly launched by Ghidra inherits the 
GhidraScript / FlatProgramAPI.

The Python module that Ghidra directly launches is always called __main__
So if we import everything from that module, this library will behave as if
Ghidra directly launched it.

comment copied from: external_module_callee.py
"""
from __main__ import *

import logging

log = logging.getLogger("script-logger")
handler = logging.StreamHandler()

log.addHandler(handler)
log.setLevel(logging.DEBUG)

"""
Dump object attributes to console
"""
def dump(obj):

    log.debug("Dumping object attributes: %s\n", obj)
    log.debug("Object type: %s\n", str(type(obj)))
    log.debug("Attributes:\n")

    for attr in dir(obj):
        try:
            printf("\t%-30s: %s\n", attr, getattr(obj,attr))
        except:
            # The object attribute is write-only: cannot get value
            log.error("\t%-30s: %s\n", attr, "ERROR: Cannot get value")


"""
Get a list of all FunctionDB's from the currentProgram listing
"""
def get_all_funcs():

    listing = currentProgram.getListing()
    func_iter = listing.getFunctions(True)

    return list(func_iter)


"""
Print all function names given a list of FunctionDB's
"""
def print_all_func_names(func_list):

    log.debug("Printing list of functions: \n")

    for func in func_list:
        func_name = func.getName()
        printf("\t%-10s: %s\n", str(func.body.minAddress), func_name)    

