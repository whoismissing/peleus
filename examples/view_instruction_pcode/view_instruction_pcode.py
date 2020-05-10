"""
Print the Pcode operations for the instruction at the currentAddress

Useful to setup as a keybinding.
"""

def print_current_addr_pcode():

    print currentAddress

    listing = currentProgram.getListing()
    current_instruction = listing.getInstructionAt(currentAddress)
    pcode_ops = current_instruction.getPcode()

    for pcode in pcode_ops:
        print pcode


def main():
    print_current_addr_pcode()


main()

