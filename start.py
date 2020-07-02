import argparse
from analysis.tracer.tracer import trace
from analysis.gen_pocs import gen_pocs

# case = "fastbin_dup"
# case = "house_of_spirit"
# case = "unsafe_unlink"
case = "tcache_poisoning"
folder = "./tests/how2heap_" + case + "/"

config = folder + "analysis.yaml"
binary = folder + case + ".bin"
source = folder + case + ".c"
desc = folder + case + ".bin-desc.yaml"
result = folder + case + ".bin-result.yaml"

# config = "./tests/how2heap_test/analysis.yaml"
# binary = "./tests/how2heap_test/heap_test.bin"



# trace(config, binary)
# gen_pocs(config, binary, result, desc, source)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find heap corruptions')
    parser.add_argument('action', metavar='<identify|gen|trace|poc|other>', type=str,
                        choices=['identify', 'trace', 'gen', 'poc','other'],
                        help='Please give me an action')
    parser.add_argument('-e', '--exploit', metavar='exploit_model', type=str,
                        help='Please give me an exploit model')

    args = parser.parse_args()
    # case = "tcache_poisoning"
    case = args.exploit
    folder = "./tests/how2heap_" + case + "/"

    config = folder + "analysis.yaml"
    binary = folder + case + ".bin"
    source = folder + case + ".c"
    desc = folder + case + ".bin-desc.yaml"
    result = folder + case + ".bin-result.yaml"

    if args.action == 'trace':
        if config is None or binary is None:
            parser.error('config or binary path is wrong')
        trace(config, binary)
    elif args.action == 'poc':
        if config is None or binary is None or result is None or desc is None or source is None:
            parser.error('config or binary or result or desc or source path is wrong')
        gen_pocs(config, binary, result, desc, source)
    elif args.action == 'other':
        # case = "double_free"
        case = "arbitary_free"
        folder = "./tests/jemalloc_" + case + "/"
        config = folder + "analysis.yaml"
        binary = folder + case + ".bin"
        trace(config, binary)
    else:
        parser.error('require an action')