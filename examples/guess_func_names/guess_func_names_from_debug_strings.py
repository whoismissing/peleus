"""
Rename functions based on reference to debug strings
"""

from ghidra.program.database.references import EmptyMemReferenceIterator
from ghidra.program.model.symbol.SourceType import USER_DEFINED
from ghidra.program.util import DefinedDataIterator

import logging

from ghidra_util import log

# log obtained from 'ghidra_util.py'
log.setLevel(logging.DEBUG)

class GuessFunctionNames():

    def __init__(self):
        self.references = {}

    """
    Insert a single entry into the GuessFunctionNames.reference dictionary
    given a defined data object if there are references to the data.
    """
    def insert_reference_entry(self, data):
        refs_to = data.getReferenceIteratorTo() 
        if not isinstance(refs_to, EmptyMemReferenceIterator):
            # Function names cannot have spaces or quotes, so we replace them
            replaced_name = 'GUESS_' + data.toString().replace(' ', '_')
            new_name_entry = replaced_name.replace('"', '')
            self.references[new_name_entry] = refs_to

    """
    Initialize the dictionary of name_entries : reference_iterables called
    references.
    """
    def init_references(self):
        defined_strings = DefinedDataIterator.definedStrings(currentProgram)
        for data in defined_strings:
            self.insert_reference_entry(data)
        log.debug('references = %s' % self.references)

    """
    Rename a Function with the provided new name if the given reference address 
    is part of a function.
    """
    def rename_reference(self, new_name, reference):
        from_addr = reference.getFromAddress()
        to_addr = reference.getToAddress()

        func_manager = currentProgram.getFunctionManager()
        func = func_manager.getFunctionContaining(from_addr)
        if func is not None:
            log.info('Setting function name at address %s to %s from address %s' % (from_addr, new_name, to_addr))
            func.setName(new_name, USER_DEFINED)

    """
    Rename all references to a defined string. Append '_#' to each name.
    """
    def rename_references(self, name_entry, reference_iter):
        i = 0
        for reference in reference_iter: 
            self.rename_reference(name_entry + '_' + str(i), reference)
            i += 1

    """
    Entry-point for using GuessFunctionNames class. Obtain all known
    references to defined strings and rename all functions with a 
    reference to the defined string.
    """
    def rename_functions(self):
        self.init_references()

        for name_entry, reference_iter in self.references.items():
            self.rename_references(name_entry, reference_iter)

def main():

    guess = GuessFunctionNames()
    guess.rename_functions()

main()
