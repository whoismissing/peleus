
import gdb

# Usage: gdb -q -x gdb_output_trace.py

BINARY_FILE  = "./a.out"
TRACE_FILE   = "./trace.log"
BREAKPOINT_1 = "0x000000000040059d"
BREAKPOINT_2 = "0x0000000000400611"
ARGS = '2'

def write_pc_to_file(pc):
    with open(TRACE_FILE, 'a+') as fd:
        fd.write(pc + '\n') 


## This code will run whenever a breakpoint is hit
def stop_handler(event):
    pc = gdb.execute('x $pc', to_string=True).split()[0]
    write_pc_to_file(pc)


def init_trace_session():
    gdb.events.stop.connect(stop_handler)
    gdb.execute('file ' + BINARY_FILE)
    gdb.execute('b * ' + BREAKPOINT_1)
    gdb.execute('b * ' + BREAKPOINT_2)


def main():
    init_trace_session()

    gdb.execute('r ' + ARGS)

    while True:
        gdb.execute('ni')


main()
