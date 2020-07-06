import argparse
from analysis.tracer.tracer import trace
from analysis.gen_pocs import gen_pocs
from gen_zoo import gen_zoo
'''
usage:
ptmalloc:
    python3 start.py trace -a how2heap -e tcache_poisoning
jemalloc
    python3 start.py trace -a jemalloc -e arbitary_free
'''

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find heap corruptions')
    parser.add_argument('action', metavar='<gen|trace|poc>', type=str,
                        choices=['trace', 'gen', 'poc'],
                        help='Please give me an action')
    parser.add_argument('-e', '--exploit', metavar='exploit_model', type=str,
                        help='Please give me an exploit model', default='tcache_poisoning')

    parser.add_argument('-a', '--allocator', metavar='allocator', type=str,
                        help='Please give me an allocator', default='how2heap')
    args = parser.parse_args()
    allocator = args.allocator
    case = args.exploit

    folder = "./tests/" + allocator + "_" + case + "/"
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
    elif args.action == 'gen':
        print("gen code")
        ### usage: python3 start.py gen -a how2heap -e heap_test
        gen_zoo(config)
    else:
        parser.error('require an action')