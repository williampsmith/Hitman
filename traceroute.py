#!/usr/bin/env python

import sys
import common

def print_tr(path, status):
    for x in range(len(path)):
        msg = " "
        if status[x]:
            msg = "*"
        print " %2i: %s %s" % (x+1,
                               msg,
                               path[x])


if __name__ == '__main__':
    # www.miit.gov.cn
    target = "202.106.121.6"

    myip = None
    if len(sys.argv) < 2:
        pass
    else:
        target = sys.argv[1]

    tr = common.PacketUtils(dst=target)
    res = tr.traceroute(target, 32)
    print_tr(res[0], res[1])
