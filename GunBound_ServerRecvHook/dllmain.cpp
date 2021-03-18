#include <Windows.h>
#include "PEHook.h"

#include <iostream>
#include <ctime>

#pragma pack(push, 1)
struct PacketHeader
{
	short Size;
	short Checksum;
	short Index;
};
#pragma pack(pop)

void dumpRawPacket(PacketHeader* pHeader, unsigned char* bufr, int pSize, bool isSend)
{
	char fpath[1024];
	SYSTEMTIME sysTime;

	GetLocalTime(&sysTime);

	// -> ALTERAR, PATH DO LOG
	sprintf(fpath, "C:\\GBWCS2\\HiddenServer\\GBSrv3_Socket\\0x%X_%db - %02d_%02d_%02d_%04d.bin", pHeader->Index, pSize, sysTime.wHour, sysTime.wMinute, sysTime.wSecond, sysTime.wMilliseconds);

	FILE *out = fopen(fpath, "wb");

	if (out != NULL)
	{
		fwrite(bufr, pSize, 1, out);
		fclose(out);
	}
}

void Recv_EncryptedFilter(PacketHeader* pHeader, unsigned char* packetBuffer)
{
	dumpRawPacket(pHeader, packetBuffer, pHeader->Size - 6, false);

	// Season 2 V6.72 Channel Message Color
	// Starts from 101 until 116
	if (pHeader->Index == 0x2010)
	{
		unsigned char TextColorPallet[16] = { 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74 };
		srand(time(NULL));
		packetBuffer[0] = TextColorPallet[rand() % 15];
	}
}

__declspec(naked) void Recv_EncryptedPackets()
{
	__asm
	{
		PUSH EAX
		PUSH EDI
		PUSH EBX

		MOV EAX, DWORD PTR SS : [ESP + 52]
		MOV EAX, DWORD PTR DS : [EAX + 24]

		IMUL EDI, 0xC
		SUB EBX, EDI

		PUSH EBX
		PUSH EAX
		CALL Recv_EncryptedFilter
		ADD ESP, 8

		POP EBX
		POP EDI
		POP EAX

		POP EDI
		POP ESI
		POP EBP
		MOV AL, 1
		PUSH 0x412526
		RETN
	}
}

void Recv_AllPacketsFilter(PacketHeader* pHeader)
{
	if (pHeader->Index != 0)
		dumpRawPacket(pHeader, (unsigned char*)pHeader, pHeader->Size, false);
}
__declspec(naked) void Recv_AllPackets()
{
	__asm
	{
		PUSH EAX

		MOV EAX, DWORD PTR DS : [ESI + 24]
		PUSH EAX
		CALL Recv_AllPacketsFilter
		ADD ESP, 4

		POP EAX

		CMP EAX, 0x3430
		PUSH 0x42BA0E
		RETN
	}
}

void InstallHooks()
{
	JMP_NEAR(0x412521, Recv_EncryptedPackets);
	//JMP_NEAR(0x42BA09, Recv_AllPackets);
}

int __stdcall DllMain(HINSTANCE hInstDLL, DWORD catchReason, LPVOID lpResrv)
{
	if (catchReason == DLL_PROCESS_ATTACH)
	{
		DWORD dwOldProtectFlag_text;

		VirtualProtect((void*)0x401000, 0x5E000, PAGE_READWRITE, &dwOldProtectFlag_text);

		InstallHooks();

		VirtualProtect((void*)0x401000, 0x5E000, dwOldProtectFlag_text, &dwOldProtectFlag_text);
	}
	else if (catchReason == DLL_PROCESS_DETACH)
	{
		FreeLibrary(hInstDLL);
	}

	return TRUE;
}