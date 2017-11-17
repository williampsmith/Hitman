#!/usr/bin/env python

import sys
import common

if __name__ == '__main__':
    # www.miit.gov.cn                                                           
    target = "202.106.121.6"
    msg = open("msg.txt").read()
    
    myip = None
    if len(sys.argv) < 3:
        pass
    else:
        target = sys.argv[2]

    tr = common.PacketUtils(dst=target)
    res = tr.evade(target, msg, int(sys.argv[1]))
    print res
    



