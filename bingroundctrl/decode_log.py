#!/usr/bin/env python
# Copyright (c) 2016, SafeBreach
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys
import binascii
import string
import time


####################
# Global Variables #
####################

__version__ = "1.0"
__author__ = "Itzik Kotler"
__copyright__ = "Copyright 2016, SafeBreach"

# "Safe Base64" to "Normal Base64" Table
safeb64_to_normalb64 = string.maketrans('_-', '+/')


#############
# Functions #
#############

def _decode_base64(s):
    try:
        return s.decode('base64')
    except binascii.Error:
        return _decode_base64(s + "=")


def parse_entry(entry):
    global safeb64_to_normalb64

    try:
        # "Sep 29 21:18:56 ns1 named[3514]: client 62.175.30.19#7642 (i90.p3184.Cg.argcargvenvp.com): query: i90.p3184.Cg.argcargvenvp.com IN AAAA -E (10.12.0.6)"
        (msg_seq_id, pid, raw_data) = entry.split()[7][1:-2].split('.')[:3]
    except ValueError:
        # "09-Dec-2016 23:21:49.969 client 76.96.15.71#54258 (i1.p5428.Cg.argcargvenvp.com): query: i1.p5428.Cg.argcargvenvp.com IN A -ED (10.12.0.6)"
        (msg_seq_id, pid, raw_data) = entry.split()[6][:-2].split('.')[:3]

    # Transform "Safe Base64" to "Normal" Base64
    base64_str = raw_data.translate(safeb64_to_normalb64)

    # Return Message Sequence ID (without the preifx 'i'), PID (without the prefix 'p') and Decoded Base64 Buffer
    return int(msg_seq_id[1:]), int(pid[1:]), _decode_base64(base64_str)


def main(argv):
    pid_order = []
    pid_buffer = {}
    output_buffer = ""

    if len(argv) < 2:
        print "usage: %s [<INPUT FILE> | -S <STRING>]"
        return 1

    if argv[1] == '-S':

        try:
            (msg_seq_id, pid, data) = parse_entry(argv[2])

            # As long as it's not empty lines (i.e. only NL) ...
            if data != '\n':
                print "%s [PID #%d]: %s" % (time.asctime(), pid, data)

        except Exception:
            pass

    else:

        with open(argv[1], 'r') as f:
            for line in f.readlines():

                if line.find('IN A -ED ') == -1:
                    continue

                try:

                    (msg_seq_id, pid, data) = parse_entry(line)

                    if pid_order.count(pid) == 0:
                        pid_order.append(pid)
                        pid_buffer[pid] = {}

                    pid_buffer[pid][msg_seq_id] = data

                except Exception:
                    pass

        # For each PID
        for pid in pid_order:
            output_buffer = ""

            print "*** START MESSAGES FROM PID %d ***" % (pid)

            # Iterate over all Messages from given PID
            for msg_id in xrange(0, max(pid_buffer[pid].keys())):
                data = pid_buffer[pid].get(msg_id, "\n MISSING DATA! \n")

                if data == '\n':
                    # Flush Buffer
                    print "[%d]: %s" % (pid, output_buffer)
                    output_buffer = ""
                else:
                    # Buffer til NL ...
                    output_buffer = output_buffer + data

            # No NL but EOF? Flush!
            if output_buffer:
                print output_buffer
                output_buffer = ""

            print "*** END MESSAGES FROM PID %d ***" % (pid)


###############
# Entry Point #
###############

if __name__ == "__main__":
    sys.exit(main(sys.argv))
