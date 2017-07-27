#!/usr/bin/env python
#
# Copyright (c) 2016, SafeBreach
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#  1. Redistributions of source code must retain the above
# copyright notice, this list of conditions and the following
# disclaimer.
#
#  2. Redistributions in binary form must reproduce the
# above copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials provided with
# the distribution.
#
#  3. Neither the name of the copyright holder
# nor the names of its contributors may be used to endorse or promote
# products derived from this software without specific prior written
# permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
# AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import argparse
import sys
import hashlib
import string
import os
import os.path
import tempfile
import re
import shlex


####################
# Global Variables #
####################

__version__ = "1.0"
__author__ = "Itzik Kotler"
__copyright__ = "Copyright 2017, SafeBreach"


##########
# Consts #
##########

ESCAPE_FMT_STRINGS = re.compile(r'(%[a-zA-Z0-9.]+)')
ESCAPE_NEWLINE_IN_STRINGS = re.compile(r'".*?"', re.DOTALL)

PYTHON_LIST_TO_C_ARRAY_FIXUP = string.maketrans("[]", "{}")

ROCKET_C_TMPL = \
"""
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * Consts
 */

#ifndef BINROCKET_VERSION
 #define BINROCKET_VERSION "%(ROCKET_VERSION)s"
#endif

#ifndef MAGICNUMBER
 #define MAGICNUMBER "%(SOURCE_MAGICNUMBER)s"
#endif

// This is a workaround, CL hangs when trying to initialize BINARY_SATELLITE with C_BYTE_ARRAY directly.

UCHAR _aData[] = %(C_BYTE_ARRAY)s;

UCHAR *_aDefaultArgv[] = %(C_DEFAULTARGV_ARRAY)s;

/*
 * Data Structures
 */

typedef struct _BINARY_SATELLITE {
    LPSTR pszSourceFilename;
    LPSTR pszDestFilename;
    LPSTR pDataMD5Hash;
    LPSTR pData;
    DWORD dwDataSize;
} BINARY_SATELLITE;
typedef BINARY_SATELLITE *PBINARY_SATELLITE;

/*
 * Functions
 */

void print_error(char *blame) {
    LPVOID lpMsgBuf;
    DWORD dwMsgID;

    dwMsgID = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwMsgID,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    printf("%s: (ERROR #%d) %s", blame, dwMsgID, lpMsgBuf);

    if (lpMsgBuf)
        LocalFree(lpMsgBuf);

    return ;
}

// Taken from https://opensource.apple.com/source/Libc/Libc-1044.1.2/string/FreeBSD/memmem.c

void *memmem(const void *l, size_t l_len, const void *s, size_t s_len) {
    register char *cur, *last;
    const char *cl = (const char *)l;
    const char *cs = (const char *)s;

    /* we need something to compare */
    if (l_len == 0 || s_len == 0)
        return NULL;

    /* "s" must be smaller or equal to "l" */
    if (l_len < s_len)
        return NULL;

    /* special case where s_len == 1 */
    if (s_len == 1)
        return memchr(l, (int)*cs, l_len);

    /* the last position where its possible to find "s" in "l" */
    last = (char *)cl + l_len - s_len;

    for (cur = (char *)cl; cur <= last; cur++)
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
            return cur;

    return NULL;
}

int main(int argc, char **argv, char **envp) {
    BINARY_SATELLITE payload = { "%(SOURCE_FILENAME)s", "%(DEST_FILENAME)s", "%(SOURCE_MD5)s", _aData, %(C_BYTE_ARRAY_SIZE)d };
    HANDLE hFile;
    DWORD dwBytesWritten = 0, iRetVal = 0, iCmdOptVectorSize = argc;
    BOOL bErrorFlag = FALSE, bStopAndExit = FALSE, bRunAfterSave = FALSE;
    LPSTR pszCmdOptName, pszCmdOptValue, pWriteableSectionStart, *pszCmdOptVector = argv;
    int i;

    // User Input or Default?
    if (argc == 1) {
        iCmdOptVectorSize = %(C_DEFAULTARGV_ARRAY_SIZE)d;
        pszCmdOptVector = _aDefaultArgv;
    }

    // Process Command Line Arguments
    for (i = 1; i < iCmdOptVectorSize; i++) {

        if (bStopAndExit == TRUE)
            break;

        if (*pszCmdOptVector[i] == '/') {
            pszCmdOptName = pszCmdOptVector[i]+1;

            pszCmdOptValue = strchr(pszCmdOptName, ':');
            if (pszCmdOptValue != NULL)
                pszCmdOptValue++;

            switch (pszCmdOptName[0]) {
                case 'H':
                case '?':
                    printf(
                        "Binary Rocket v%s built on %s %s from %s\n"
                        "\n"
                        "%s [/?] [/D] [/S:[FILENAME]] [/R] [/W:[DATA]]\n"
                        "\n"
                        "  /?\tShow this help message and exit\n"
                        "  /D\tShow information on the packed Binary Satellite and exit\n"
                        "  /S\tWrite Binary Satellite to disk as FILENAME (override DEST_FILENAME parameter)\n"
                        "  /R\tRun Binary Satellite after writing it to the disk\n"
                        "  /W\tWrite DATA into the Binary Satellite writeable section\n",
                        BINROCKET_VERSION,
                        __DATE__,
                        __TIME__,
                        __FILE__,
                        argv[0]
                        );
                    bStopAndExit = TRUE;
                    break;

                case 'D':
                    printf(
                        "Binary Rocket v%s built on %s %s from %s\n"
                        "\n"
                        "Source Filename: %s\n"
                        "Source Filename MD5 Checksum: %s\n"
                        "Source Filename MAGICNUMBER: \\"%s\\" (%d bytes)\n"
                        "Destination Filename: %s\n"
                        "Destination Filename Size: %d bytes\n",
                        BINROCKET_VERSION,
                        __DATE__,
                        __TIME__,
                        __FILE__,
                        payload.pszSourceFilename,
                        payload.pDataMD5Hash,
                        MAGICNUMBER,
                        strlen(MAGICNUMBER),
                        payload.pszDestFilename,
                        payload.dwDataSize
                    );
                    bStopAndExit = TRUE;
                    break;

                case 'S':
                    if (pszCmdOptValue == NULL || strlen(pszCmdOptValue) < 1) {
                        printf("Not enough parameters - Missing FILENAME\n");
                        bStopAndExit = TRUE;
                        iRetVal = -1;
                    } else {
                        printf("Changing DEST_FILENAME from %s to %s\n", payload.pszDestFilename, pszCmdOptValue);
                        payload.pszDestFilename = strdup(pszCmdOptValue);
                    }
                    break;

                case 'R':
                    bRunAfterSave = TRUE;
                    break;

                case 'W':
                    if (pszCmdOptValue == NULL || strlen(pszCmdOptValue) < 1) {
                        printf("Not enough parameters - Missing DATA\n");
                        bStopAndExit = TRUE;
                        iRetVal = -1;
                    } else {
                        printf("Looking for MAGICNUMBER in (packed) %s ...\n", payload.pszSourceFilename);
                        pWriteableSectionStart = memmem(payload.pData, payload.dwDataSize, MAGICNUMBER, strlen(MAGICNUMBER));
                        if (pWriteableSectionStart == NULL) {
                            printf("Unable to find MAGICNUMBER.\nExiting ...\n");
                            bStopAndExit = TRUE;
                            iRetVal = -1;
                        } else {
                            CopyMemory(pWriteableSectionStart, pszCmdOptValue, strlen(pszCmdOptValue));
                            printf("Wrote %d bytes to (packed) %s successfully.\n", strlen(pszCmdOptValue), payload.pszSourceFilename);
                        }
                    }
                    break;

                default:
                    printf("Invalid option - \\"%s\\".\n", pszCmdOptName);
                    bStopAndExit = TRUE;
                    iRetVal = -1;
                    break;
            }

        } else {
            printf("Invalid option - \\"%s\\".\n", *pszCmdOptVector[i]);
            bStopAndExit = TRUE;
            iRetVal = -1;
        }
    }

    if (bStopAndExit == TRUE)
        return iRetVal;

    printf("Creating %s ...\n", payload.pszDestFilename);

    hFile = CreateFileA(payload.pszDestFilename,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        print_error(payload.pszDestFilename);
        return -1;
    }

    printf("Writing %d bytes to %s.\n", payload.dwDataSize, payload.pszDestFilename);

    bErrorFlag = WriteFile(
        hFile,
        payload.pData,
        payload.dwDataSize,
        &dwBytesWritten,
        NULL);

    if (bErrorFlag == FALSE || dwBytesWritten != payload.dwDataSize) {
        print_error(payload.pszDestFilename);
        CloseHandle(hFile);
    }

    printf("Wrote %d bytes to %s successfully.\n", dwBytesWritten, payload.pszDestFilename);

    CloseHandle(hFile);

    printf("Closed %s\n", payload.pszDestFilename);

    if (bRunAfterSave == TRUE) {
        PROCESS_INFORMATION pi;
        STARTUPINFO si;

        ZeroMemory( &si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory( &pi, sizeof(pi));

        printf("Running %s ...\n", payload.pszDestFilename);

        if (!CreateProcess(payload.pszDestFilename, payload.pszDestFilename, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
            print_error(payload.pszDestFilename);
    }

}
"""

#############
# Functions #
#############

def pylist2carray(array):
    array_length = len(array)
    return (array_length, str(array).translate(PYTHON_LIST_TO_C_ARRAY_FIXUP, "'"))


def main(argv):
    parser = argparse.ArgumentParser(description="Binary Rocket Factory")
    parser.add_argument('infile', metavar='IN_FILE', type=argparse.FileType('rb'), help='Input "Binary Satellite" File')
    parser.add_argument('outfile', nargs='?', metavar='OUT_FILE', type=argparse.FileType('w'), default=sys.stdout,
                        help='Output "Binary Rocket" File (default: STDOUT)')
    parser.add_argument('-q', '--quiet', action='store_true')
    parser.add_argument('--version', action='version', version='%(prog)s v' + __version__)
    parser.add_argument('--set-destfilename', metavar='FILENAME', help='Set Unpacked Filename (default: Temporary Filename with an .EXE extension)', default=os.path.basename(tempfile.mktemp()) + '.exe')
    parser.add_argument('--set-magicnumber', metavar='STRING', help='Set Custom Magic Number (default: \'.oO\')', default='.oO')
    parser.add_argument('--set-defaultopts', metavar='STRING', help='Set Default Command-line Options (default: \'/W:"Shazam" /R\')', default='/W:"Shazam" /R')

    args = parser.parse_args(argv[1:])

    # Calculate & Convert
    infile_data = args.infile.read()
    (c_byte_array_size, c_byte_array) = pylist2carray(map(lambda x: hex(ord(x)), infile_data))
    # "FOOBAR.EXE" is a fake argv[0] placeholder, it's always skipped (i.e. for (i = 1; ...)) over in the Line #110 of ROCKET.C
    (c_dflt_argv_size, c_dflt_argv) = pylist2carray(map(lambda x: '"' + str(x) + '"', shlex.split("FOOBAR.EXE " + args.set_defaultopts)))

    rocket_parameters = {'C_BYTE_ARRAY': c_byte_array, 'C_BYTE_ARRAY_SIZE': c_byte_array_size,
                         'SOURCE_FILENAME': args.infile.name.replace('\\', '\\\\'), 'SOURCE_MD5': hashlib.md5(infile_data).hexdigest(),
                         'ROCKET_VERSION': __version__, 'SOURCE_MAGICNUMBER': args.set_magicnumber,
                         'DEST_FILENAME': args.set_destfilename.replace('\\', '\\\\') , 'C_DEFAULTARGV_ARRAY_SIZE': c_dflt_argv_size,
                         'C_DEFAULTARGV_ARRAY': c_dflt_argv}

    if not args.quiet:
        print "mkbinrocket.py v" + __version__
        print " "
        print "=" * 50
        print "IN  FILENAME: %s" % rocket_parameters['SOURCE_FILENAME']
        print "IN  FILENAME MD5: %s" % rocket_parameters['SOURCE_MD5']
        print "IN  FILENAME MAGICNUMBER: \"%s\" (%d bytes)" % (rocket_parameters['SOURCE_MAGICNUMBER'], len(rocket_parameters['SOURCE_MAGICNUMBER']))
        print "OUT FILENAME: %s" % rocket_parameters['DEST_FILENAME']
        print "OUT FILENAME SIZE: %d bytes" % rocket_parameters['C_BYTE_ARRAY_SIZE']
        print "OUT FILENAME DEFAULT ARGV: \"%s\"" % rocket_parameters['C_DEFAULTARGV_ARRAY']
        print "=" * 50

    # Convert C Source Code to Python-friendly String for Processing
    _rocket_code = ESCAPE_FMT_STRINGS.sub(r'%\1', ROCKET_C_TMPL)

    # Taken from http://stackoverflow.com/questions/8219502/how-could-i-remove-newlines-from-all-quoted-pieces-of-text-in-a-file
    rocket_code = ESCAPE_NEWLINE_IN_STRINGS.sub(lambda x: x.group().replace('\n', '\\n'), _rocket_code)

    rocket_code = rocket_code % rocket_parameters

    args.outfile.write(rocket_code)

    if not args.quiet:
        print " "
        print "Wrote %s (%d bytes)." % (args.outfile.name, len(rocket_code))
        print " "
        print "Open 'Developer Command Prompt for VS2015'"
        print "Write: CL /O2 /D \"WIN32\" /D \"NDEBUG\" /D \"_CONSOLE\" /MD %s" % args.outfile.name

###############
# Entry Point #
###############

if __name__ == "__main__":
    sys.exit(main(sys.argv))
