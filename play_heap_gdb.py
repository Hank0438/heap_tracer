import re
import logging, coloredlogs
import time
import angelheap
from pwn import *
timestamp = int(time.time())

coloredlogs.install()
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)

# def r2_test():
#     import r2pipe
#     import json
#     r2 = r2pipe.open("./playground.bin")
#     r2 = r2pipe.open("./tests/how2heap_fastbin_dup/pocs/malloc_non_heap/fastbin_dup.bin/bin/poc_0_0.bin")
#     r2.cmd('aaa')
#     print(r2.cmd("afl"))
#     print(r2.cmdj("aflj"))  # evaluates JSONs and returns an object
#     r2.cmd('s main')
#     functions = [func for func in json.loads(r2.cmd('aflj'))]
#     with open('profile.rr2', 'w+') as f:
#         f.write('#!/path/to/rarun2\nstdin="1222"')
#     r2.cmd('e dbg.profile=profile.rr2')
#     r2.cmd('doo; dm')

#     import r2pipe

#     R2 = r2pipe.open('/bin/ls')                         
#     R2.cmd("aaaa")

#     for func in R2.cmd('afbj @@f').split("\n")[:-1]:
#         print(func)

#     # sth = [hex(eval(func)[0]['addr']) for func in R2.cmd('afbj @@f').split("\n")[:-1]]
#     # print(sth)

binary = "./tests/how2heap_fastbin_dup/pocs/malloc_non_heap/fastbin_dup.bin/bin/poc_0_0.bin"
# binary = "./tests/how2heap_fastbin_dup/fastbin_dup.bin"
caller_address = []
transactions = []

'''
transactions
    1. malloc(num)
        ctrl_data[num].global_var = malloc(malloc_sizes[num]);
    2. fill_chunk(num)
        for (int i=0; i < fill_sizes[num]; i+=8) {
            read(0, ((uint8_t *)ctrl_data[num].global_var)+i, 8);
        }
    3. free(num)
        free(ctrl_data[num].global_var);
    4. uaf(num)
        read(FD, ctrl_data[num].global_var, header_size);
    5. overflow(num, overflow_num)
        offset = mem2chunk_offset;
        read(FD, ((char *) ctrl_data[num].global_var)-offset, overflow_sizes[overflow_num]);
    6. fake_free(num)
        free(((uint8_t *) &sym_data[num].data) + mem2chunk_offset);
                


'''


def dump_heap_memory(dump_files=False, show_gdb_res=False):
    global binary, caller_address, transactions
    import subprocess
    grep_item = ["read@plt", "free@plt", "malloc@plt"]
    process = subprocess.Popen(['objdump', "-d", binary, "-M", "intel"], stdout=subprocess.PIPE)
    stdout = process.communicate()[0].decode().split("\n")
    for idx, asm in enumerate(stdout):
        for g in grep_item:
            if (g in asm) and ("call" in asm):
                # print(asm)
                transactions.append(asm)
                asm = stdout[idx+1]
                addr = int(asm[:asm.index(":")].strip(" "), 16)
                print(hex(addr))
                caller_address.append(addr)
        # if (" <main>:" in asm):
        #     addr = int(asm[:asm.index(":")-7].strip(" "), 16)
        #     print(hex(addr))
        #     caller_address.append(addr)


    # input("@")
    # from pwn import *
    # r = process(binary)


    from pygdbmi.gdbcontroller import GdbController
    from pprint import pprint

    gdbmi = GdbController()
    # print(gdbmi.get_subprocess_cmd()) 
    logger.info('-file-exec-file ' + binary)
    response = gdbmi.write('-file-exec-file ' + binary)
    if show_gdb_res: pprint(response)

    # logger.info("break main")
    # response = gdbmi.write('break main')
    # pprint(response)

    for c in caller_address:
        logger.info('-break-insert *' + str(c))
        response = gdbmi.write('-break-insert *' + str(c))
        if show_gdb_res: pprint(response)

    # logger.info('-exec-run')
    # response = gdbmi.write('-exec-run')
    # pprint(response)

    # logger.info('attach')
    # response = gdbmi.write('attach')
    # pprint(response)

    logger.info('run')
    response = gdbmi.write('run')
    if show_gdb_res: pprint(response)

    # logger.info('-exec-continue')
    # response = gdbmi.write('-exec-continue')
    # pprint(response)


    logger.info('info proc mappings')
    response = gdbmi.write('info proc mappings')
    if show_gdb_res: pprint(response)


    heap_addr = []
    for entry in response:
        if "[heap]" in entry['payload']:
            # print(entry)
            heap_addr = re.findall(r'0x\d+', entry['payload'])
            # print(regex)
            break

    for transaction_count in range(len(caller_address)):

        if dump_files:
            dump_filename = "heap_gdb_" + str(timestamp) + "_" + str(transaction_count)
            dump_payload = "dump memory " + dump_filename + " " + heap_addr[0] + " " + heap_addr[1]  
            logger.info(dump_payload)
            response = gdbmi.write(dump_payload)
            if show_gdb_res: pprint(response)

        logger.info('-exec-continue')
        response = gdbmi.write('-exec-continue')
        if show_gdb_res: pprint(response)

    # except:
        # print("gdb write file error")
    # pprint(response)



def diff_heap_memory():
    global transactions
    for cnt in range(len(transactions)):
        f = open("./heap_gdb_1590059065_" + str(cnt), "rb")
        memory = f.read()
        logger.info('show_tcache_entry '+ str(cnt))
        show_tcache_entry(memory, transactions[cnt])
        # try:
        # except:
        #     print("sth wrong")

def byte_to_hex(data, shift):
    return hex(u64(data)).rjust(shift)

def parse_yaml(config_file):
    import yaml
    f = open(config_file)
    config = yaml.load(f, Loader=yaml.SafeLoader)
    print(config)
    return config
    # for k, v in config.items():
    #     print(f"k = {k}, v = {v}")


def show_tcache_entry(memory, transaction=""):
    '''
    typedef struct tcache_entry
    {
        struct tcache_entry *next;
    } tcache_entry;

    typedef struct tcache_perthread_struct
    {
        char counts[TCACHE_MAX_BINS];
        tcache_entry *entries[TCACHE_MAX_BINS];
    } tcache_perthread_struct;
    '''
    TCACHE_MAX_BINS = (0x250 - 0xb0 ) // 0x8
    print("TCACHE_MAX_BINS: ", TCACHE_MAX_BINS)
    print("transaction: ", transaction)
    tcache = {}
    tcache['header'] = memory[0x0:0x10]
    tcache['perthread_struct_count'] = memory[0x10:0x50]
    tcache['perthread_struct_entries'] = memory[0x50:0x250]
    print("="*49)
    print(f"+ header: {byte_to_hex(tcache['header'][:0x8], 0x12)} {byte_to_hex(tcache['header'][0x8:0x10], 0x12)} ")
    print("="*49)
    for idx in range(TCACHE_MAX_BINS):
        cnt = tcache['perthread_struct_count'][idx*1:(idx+1)*1]
        cnt = u64(cnt.ljust(8, b"\x00"))
        if cnt != 0:
            print(f"+ count[{hex((idx+1)*0x10).rjust(5)}]: {hex(cnt).rjust(0xc)}")
    print("="*49)
    for idx in range(TCACHE_MAX_BINS):
        ent = tcache['perthread_struct_entries'][idx*8:(idx+1)*8]
        if u64(ent) != 0:
            print(f"+ entries[{hex((idx+1)*0x10).rjust(5)}]: {byte_to_hex(ent, 0xc)}")

# for unknown allocator
def show_offset_change():
    pass

def bar():
    import time
    import sys

    toolbar_width = 40

    # setup toolbar
    sys.stdout.write("[%s]" % (" " * toolbar_width))
    sys.stdout.flush()
    sys.stdout.write("\b" * (toolbar_width+1)) # return to start of line, after '['

    for i in range(toolbar_width):
        time.sleep(0.1) # do real work here
        # update the bar
        sys.stdout.write("-")
        sys.stdout.flush()

    sys.stdout.write("]\n") # this ends the progress bar


if __name__ == "__main__":
    config_file="/media/sf_Documents/AEG/AEG/heaphopper_tracer/tcache_parser.yaml"
    # bar()
    #dump_heap_memory(dump_files=True, show_gdb_res=True)
    diff_heap_memory()


    # config = parse_yaml(config_file)

    # angelheap.hello()
    # angelheap.get_tcache()
    # angelheap.get_heap_info()
    '''
    docker run --rm -v /home/hank0438:/foo -w /foo -i -t --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ubuntu:20.04 bash
    '''
