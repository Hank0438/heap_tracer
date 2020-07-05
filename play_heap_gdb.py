import re
import logging, coloredlogs
from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import time
# import angelheap
from pwn import *
timestamp = int(time.time())

coloredlogs.install()
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)

'''
# transactions
    1. malloc(num)
        ctrl_data[num].global_var = malloc(malloc_sizes[num]);
    2. fill_chunk(num)
        for (int i=0; i < fill_sizes[num]; i+=8) {
            read(0, ((uint8_t *)ctrl_data[num].global_var)+i, 8);
        }
    3. free(num)
        free(ctrl_data[num].global_var);
    4. overflow(num, overflow_num)
        offset = mem2chunk_offset;
        read(FD, ((char *) ctrl_data[num].global_var)-offset, overflow_sizes[overflow_num]);

# the below transaction only valid for free chunk:
    5. uaf(num)
        read(FD, ctrl_data[num].global_var, header_size);
    6. fake_free(num)
        free(((uint8_t *) &sym_data[num].data) + mem2chunk_offset);
    7. double_free(num)
        free(ctrl_data[num].global_var);
'''

def get_transaction_breakpoint():
    global binary, caller_address, transactions
    import subprocess
    grep_item = ["read@plt", "free@plt", "malloc@plt", "calloc@plt", "realloc@plt"]
    process = subprocess.Popen(['objdump', "-d", binary, "-M", "intel"], stdout=subprocess.PIPE)
    stdout = process.communicate()[0].decode().split("\n")
    for idx, asm in enumerate(stdout):
        for g in grep_item:
            if (g in asm) and ("call" in asm):
                # print(asm)
                transactions.append(asm)
                addr = {}
                asm = stdout[idx]
                addr['before'] = int(asm[:asm.index(":")].strip(" "), 16)
                asm = stdout[idx+1]
                addr['after'] = int(asm[:asm.index(":")].strip(" "), 16)
                print(hex(addr['after']))
                caller_address.append(addr)
        # if (" <main>:" in asm):
        #     addr = int(asm[:asm.index(":")-7].strip(" "), 16)
        #     print(hex(addr))
        #     caller_address.append(addr)


def dump_heap_memory(dump_files=False, show_gdb_res=False):
    global binary, caller_address, transactions, gdbmi
    file_path = "/tmp/heap_gdb_" + str(timestamp)

    gdb_command('-file-exec-file ' + binary, show_gdb_res=True)

    for c in caller_address:
        gdb_command('-break-insert *' + str(c['after']), show_gdb_res=True)

    gdb_command('run', show_gdb_res=True)

    res = gdb_command('p main_arena', show_gdb_res=False)
    main_arena = main_arena_parser(res)
    print("main_arena['fastbinsY']: ", main_arena['fastbinsY'])
    print("main_arena['top']: ", main_arena['top'])

    response = gdb_command('info proc mappings', show_gdb_res=True)

    heap_addr = []
    for entry in response:
        if "[heap]" in entry['payload']:
            # print(entry)
            heap_addr = re.findall(r'0x\d+', entry['payload'])
            # print(regex)
            break

    for transaction_count in range(len(caller_address)):
        if dump_files:
            dump_filename = file_path + "_" + str(transaction_count)
            dump_payload = "dump memory " + dump_filename + " " + heap_addr[0] + " " + heap_addr[1]  
            response = gdb_command(dump_payload, show_gdb_res=True)
            for entry in response:
                if entry['message'] == "error":
                    return

        response = gdb_command('-exec-continue', show_gdb_res=True)
        for entry in response:
            if entry['message'] == "error":
                return


def diff_heap_memory(file_path="/tmp/heap_gdb_1593934091_"):
    global transactions
    for cnt in range(len(transactions)):
        dump_filename = file_path + str(cnt)
        f = open(dump_filename, "rb")
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
    

def dump_main_arena(dump_files=False, show_gdb_res=False):
    global binary, caller_address, transactions
    file_path = "/tmp/heap_gdb_" + str(timestamp)

    gdb_command('-file-exec-file ' + binary, show_gdb_res=True)

    for c in caller_address:
        gdb_command('-break-insert *' + str(c['after']), show_gdb_res=False)

    gdb_command('run', show_gdb_res=True)

    res = gdb_command('p main_arena', show_gdb_res=False)
    main_arena = main_arena_parser(res)
    # print(main_arena['bins'])
    print("main_arena['top']: ", main_arena['top'])

def main_arena_parser(res):
    res = gdb_response_concat(res)

    res = res[res.find("{")+1:-3]
    res = res.replace(" = ", ":")
    res = res.replace(" ", "")
    main_arena = {}
    is_array = False
    is_element = False
    arr = []
    element = ""
    key = ""
    for idx, r in enumerate(res):
         
        if r is ",":
            if res[idx-1] is "}":
                continue
            if is_array is False:
                main_arena[key] = element
                # print(main_arena)
                key = ""
                element = ""
                is_element = False
            else:
                arr.append(element)
                element = ""
            continue

        if r is ":":
            main_arena[key] = ""
            is_element = True
            continue

        if (r is "{") and (is_array is False):
            is_array = True
            main_arena[key] = {}
            arr = []
            continue

        if (r is "}") and (is_array is True):
            is_array = False
            is_element = False
            arr.append(element)
            main_arena[key] = arr
            # print(main_arena)
            arr = []
            key = ""
            element = ""
            continue
        
        if (is_element is True):
            element += r
        else:
            key += r

    return main_arena
        
        
def gdb_response_concat(res):
    payload = ""
    for r in res:
        if (r['type'] == "console") & (r['stream'] == "stdout"):
            payload += r['payload']
    return payload

def gdb_command(cmd, show_gdb_res=True):
    global gdbmi
    logger.info(cmd)
    response = gdbmi.write(cmd)
    if show_gdb_res: pprint(response)
    return response

if __name__ == "__main__":
    # binary = "./tests/how2heap_fastbin_dup/pocs/malloc_non_heap/fastbin_dup.bin/bin/poc_0_0.bin"
    # binary = "./tests/how2heap_fastbin_dup/fastbin_dup.bin"
    # binary = "./tests/how2heap_tcache_poisoning/tcache_poisoning.bin"
    binary = "./tests/how2heap_heap_test/heap_test.bin"
    config_file = "/media/sf_Documents/AEG/AEG/heaphopper_tracer/tcache_parser.yaml"
    mem_file_path = "/tmp/heap_gdb_1593954912_"
    caller_address = []
    transactions = []

    gdbmi = GdbController()
    get_transaction_breakpoint()
    # print(caller_address)
    dump_heap_memory(dump_files=True, show_gdb_res=True)
    diff_heap_memory(mem_file_path)



    # dump_main_arena()

    # config = parse_yaml(config_file)

    # angelheap.hello()
    # angelheap.get_tcache()
    # angelheap.get_heap_info()
    '''
    docker run --rm -v /home/hank0438:/foo -w /foo -i -t --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ubuntu:20.04 bash
    '''
