#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <sstream>
#include <iomanip>
#include "../libread/libread/libread.h"

#pragma comment(lib, "BCrypt.lib")

static const char *AdoRdrPath = "C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe";
static bool ShouldStop = false;

// if we're incorrectly identifying the offset of ThreadPingEventReady, set and recompile here
static int TARGET_OFFSET = 0;
static int CallCount = 0;
static int CallDup = 0;

enum MONITOR_ACTION {
	PRINT_TO_STDOUT = 1,
	LOG_TO_FILE
};

HMODULE GetModule(HANDLE hProcess)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				std::wstring wstrModName = szModName;
				std::wstring wstrModContain = L"AcroRd32.exe";
				if (wstrModName.find(wstrModContain) != std::string::npos)
					return hMods[i];
			}
		}
	}

	return nullptr;
}

// this little number helps us find the offset for the thread ping handler function. it's too annoying having to 
// update the offset for each minor version/update of Reader, so this *should* generically find it for us. seems to
// be working so far...
DWORD CaptureThreadAlertOffset()
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	HMODULE hAdoRdr = 0;
	DEBUG_EVENT dbgEvent = { 0 };
	unsigned char interrupt = 0xcc;
	DWORD dwRead = 0, dwBytes = 0, dwOffset = 0;
	DWORD dwTarget = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "RegisterWaitForSingleObject");

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	if (!CreateProcessA(AdoRdrPath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi))
	{
		printf("[-] Could not find or launch Adobe Reader! (%d)\n", GetLastError());
		return dwOffset;
	}

	// the process won't be ready to read from right away
	while (true) {
		WaitForDebugEvent(&dbgEvent, INFINITE);
		if (ReadProcessMemory(pi.hProcess, (LPCVOID)dwTarget, &dwBytes, sizeof(DWORD), &dwRead) != 0) {
			hAdoRdr = GetModule(pi.hProcess);
			break;
		}
		ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE);
	}

	// write bp
	VirtualProtectEx(pi.hProcess, (LPVOID)dwTarget, sizeof(DWORD), PAGE_READWRITE, NULL);
	if (!WriteProcessMemory(pi.hProcess, (LPVOID)dwTarget, &interrupt, sizeof(unsigned char), NULL)) 
	{
		printf("[-] Failed to write breakpoint! (%d)\n", GetLastError());
		return dwOffset;
	}

	FlushInstructionCache(pi.hProcess, (LPVOID)dwTarget, sizeof(unsigned char));

	dbgEvent = { 0 };
	ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE);
	while (true)
	{
		WaitForDebugEvent(&dbgEvent, INFINITE);
		if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			EXCEPTION_DEBUG_INFO &Exception = dbgEvent.u.Exception;
			if (Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
				CONTEXT lpContext;
				lpContext.ContextFlags = CONTEXT_ALL;

				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, dbgEvent.dwThreadId);
				GetThreadContext(hThread, &lpContext);

				//printf("EIP: %08x ESP: %08x (%08x)\n", lpContext.Eip, lpContext.Esp, (lpContext.Esp + 0xc));

				// ensure we hit the correct bp
				if (lpContext.Eip == dwTarget + 1)
				{
					ReadProcessMemory(pi.hProcess, (LPCVOID)(lpContext.Esp + 0xc), &dwOffset, sizeof(DWORD), NULL);
					dwOffset -= (DWORD)hAdoRdr;
					break;
				}

				CloseHandle(hThread);
			}
		}

		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
	}

	DebugActiveProcessStop(pi.dwProcessId);
	TerminateProcess(pi.hProcess, 0);
	return dwOffset;
}

void PrintCall(HANDLE hProcess, DWORD dwThreadId, DWORD CallEsp)
{
	DWORD dwAddress = 0;

	ReadProcessMemory(hProcess, (LPVOID)(CallEsp + 4), &dwAddress, sizeof(DWORD), NULL);
	ServerControl *control = new ServerControl(hProcess, dwAddress);

	// sanity
	if (control->channel->crosscall == NULL || 
		control->channel->ipc_tag <= 0) {
		return;
	}

	printf("[%d] ESP: %08x\tBuffer %08x\tTag %d\t%d Parameters\n", 
		dwThreadId, 
		CallEsp,
		control->channel_buffer, 
		control->channel->crosscall->tag,
		control->channel->crosscall->params_count);

	for (int i = 0; i < control->channel->crosscall->params_count; ++i) {
		if (control->channel->crosscall->parameters[i].type == WCHAR_TYPE ||
			control->channel->crosscall->parameters[i].type == UNISTR_TYPE) {
			wchar_t *str = (wchar_t*)control->channel->crosscall->parameters[i].buffer;
			wprintf(L"      %s: %s\n", ArgTypeToStringW(control->channel->crosscall->parameters[i].type), str);
		}
		else if (control->channel->crosscall->parameters[i].type == ASCII_TYPE) {
			char *str = (char*)control->channel->crosscall->parameters[i].buffer;
			printf("      %s: %s\n", ArgTypeToStringA(control->channel->crosscall->parameters[i].type), str);
		}
		else {
			printf("      %s: %08x\n",
				ArgTypeToStringA(control->channel->crosscall->parameters[i].type),
				*reinterpret_cast<DWORD*>(control->channel->crosscall->parameters[i].buffer));
		}
	}

	delete control;
}

// generate a SHA512 of the file 
std::string CreateFileHash(LPVOID lpBuffer, SIZE_T dwBufSize)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	LPVOID lpHash = NULL;
	DWORD dwHashLen = 0, dwRet = 0, cbHashObject = 0;
	PBYTE pbHashObject = NULL;

	BCryptOpenAlgorithmProvider(&hAlg, 
		BCRYPT_SHA512_ALGORITHM,
		NULL, 0);

	BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&dwHashLen, sizeof(DWORD), &dwRet, 0);

	lpHash = VirtualAlloc(NULL, dwHashLen, MEM_COMMIT, PAGE_READWRITE);

	BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
	BCryptHashData(hHash, (PBYTE)lpBuffer, dwBufSize, 0);
	BCryptFinishHash(hHash, (PBYTE)lpHash, dwHashLen, 0);

	BCryptCloseAlgorithmProvider(hAlg, 0);
	BCryptDestroyHash(hHash);
	BCryptFreeBuffer(pbHashObject);

	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (int i = 0; i < dwHashLen; ++i)
		ss << std::setw(2) << (int)(*((BYTE*)lpHash + i));

	VirtualFree(lpHash, dwRet, MEM_RELEASE);
	return ss.str().c_str();
}

/*
 Dumps a channel buffer to disk. This captures the entire channel buffer to provide an easy way to replay traffic in external tools or
 generate corpus.
 Writes all cases to local folder "capture". File names are SHA512's of the channel buffer data; this gives us a unique filename and baked in dedup.
 Easy to strip that out if you want all traffic captured.
*/
void LogCall(HANDLE hProcess, DWORD CallEsp)
{
	DWORD dwAddress = 0, dwChanLen = 0, dwWritten = 0;
	ReadProcessMemory(hProcess, (LPVOID)(CallEsp + 4), &dwAddress, sizeof(DWORD), NULL);
	ServerControl *control = new ServerControl(hProcess, dwAddress);

	// we can find the buffer size by grabbing the final parameter's offset, which is an offset to the end of the channel buffer
	DWORD idx = control->channel->crosscall->params_count - 1;
	DWORD dwEndPtr = control->channel_buffer + control->channel->crosscall->parameters[idx].offset + control->channel->crosscall->parameters[idx].size;
	dwChanLen = dwEndPtr - control->channel_buffer;
	LPVOID lpBuf = control->Read(control->channel_buffer, dwChanLen);

	std::string filehash = CreateFileHash(lpBuf, dwChanLen);
	filehash.insert(0, ".\\capture\\");
	CreateDirectoryA(".\\capture", NULL);

	HANDLE hFile = CreateFileA(filehash.c_str(),
		GENERIC_WRITE|GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		// already exists; skip it
		CallDup++;
		goto cleanup;
	}

	if (!WriteFile(hFile, lpBuf, dwChanLen, &dwWritten, NULL))
		printf("[-] FAILED to write capture file: %d\n", GetLastError());

	CloseHandle(hFile);
	CallCount++;
	
cleanup:
	VirtualFree(lpBuf, dwChanLen, MEM_RELEASE);
}

/*
 Sets a breakpoint on ThreadPingEventReady; every time it's called we parse out the channel buffer and print it
 to the screen, then continue execution. We could also duplicate the server's ping handle, but then we're in a race to fetch
 the channel buffer before it's trashed by another request. 
*/
void Monitor(DWORD dwPid, MONITOR_ACTION Action)
{
	if (TARGET_OFFSET <= 0)
		TARGET_OFFSET = CaptureThreadAlertOffset();

	if (!DebugActiveProcess(dwPid)) {
		printf("[-] Could not debug target process! (err: %d)\n", GetLastError());
		return;
	}

	byte INT = 0xcc, replaced = 0;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPid);
	HMODULE hmBase = GetModule(hProcess);

	unsigned char rint = 0xcc, op = 0;
	ReadProcessMemory(hProcess, (LPVOID)((DWORD)hmBase + TARGET_OFFSET), &op, sizeof(unsigned char), NULL);

	// write our int
	WriteProcessMemory(hProcess, (LPVOID)((DWORD)hmBase + TARGET_OFFSET), &rint, sizeof(unsigned char), NULL);
	FlushInstructionCache(hProcess, (LPVOID)(DWORD)hmBase, 1);

	bool bFirstHit = false, bTrapSet = false;
	while (true) {
		DEBUG_EVENT dbgEvent = { 0 };
		DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
		if (WaitForDebugEvent(&dbgEvent, 1000)) {
			if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
			{
				EXCEPTION_DEBUG_INFO &Exception = dbgEvent.u.Exception;
				if (Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
					if (!bFirstHit)
						bFirstHit = true;
					else
					{
						CONTEXT lpContext;
						lpContext.ContextFlags = CONTEXT_ALL;
						
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, dbgEvent.dwThreadId);
						GetThreadContext(hThread, &lpContext);

						// do something
						switch (Action)
						{
							case PRINT_TO_STDOUT:
								PrintCall(hProcess, dbgEvent.dwThreadId, lpContext.Esp);
								break;
							case LOG_TO_FILE:
								LogCall(hProcess, lpContext.Esp);
								break;
							default:
								break;
						}

						lpContext.Eip--;
						lpContext.EFlags |= 0x100;
						SetThreadContext(hThread, &lpContext);

						WriteProcessMemory(hProcess, (LPVOID)((DWORD)hmBase + TARGET_OFFSET), &op, sizeof(unsigned char), NULL);
						FlushInstructionCache(hProcess, (LPVOID)(DWORD)hmBase, 1);
						bTrapSet = true;
						CloseHandle(hThread);
					}

					dwContinueStatus = DBG_CONTINUE;
				}
				else if (Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
				{
					WriteProcessMemory(hProcess, (LPVOID)((DWORD)hmBase + TARGET_OFFSET), &rint, sizeof(unsigned char), NULL);
					FlushInstructionCache(hProcess, (LPVOID)(DWORD)hmBase, 1);
					bTrapSet = false;
					dwContinueStatus = DBG_CONTINUE;
				}
			}
		}

		// don't quit until we're sure the trap flag is cleared
		if (ShouldStop && !bTrapSet)
			break;
		
		ContinueDebugEvent(dwPid, dbgEvent.dwThreadId, dwContinueStatus);
	}

	printf("[+] Caught sigint, detaching\n");

	// ensure our breakpoint is gone
	WriteProcessMemory(hProcess, (LPVOID)((DWORD)hmBase + TARGET_OFFSET), &op, sizeof(unsigned char), NULL);
	FlushInstructionCache(hProcess, (LPVOID)(DWORD)hmBase, 1);

	DebugActiveProcessStop(dwPid);
	CloseHandle(hProcess);
}

DWORD GetIntegrityLevel(HANDLE hProcess)
{
	HANDLE hToken = INVALID_HANDLE_VALUE;
	PTOKEN_MANDATORY_LABEL pTI;
	DWORD dwLen = 0, dwTI = 0;

	OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);

	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLen);
	pTI = (PTOKEN_MANDATORY_LABEL)VirtualAlloc(NULL, dwLen, MEM_COMMIT, PAGE_READWRITE);
	GetTokenInformation(hToken, TokenIntegrityLevel, pTI, dwLen, &dwLen);

	dwTI = *GetSidSubAuthority(pTI->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTI->Label.Sid) - 1));
	VirtualFree(pTI, dwLen, MEM_RELEASE);
	return dwTI;
}

void Dump(DWORD dwPid)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPid);
	if (hProcess == NULL) {
		printf("[-] Could not open PID %d (err: %d)!\n", dwPid, GetLastError());
		return;
	}

	if (GetIntegrityLevel(hProcess) != SECURITY_MANDATORY_LOW_RID) {
		printf("[-] Target PID (%d) should be CHILD process, not broker!\n", dwPid);
		CloseHandle(hProcess);
		return;
	}

	DWORD dwMap = find_memory_map(hProcess);
	if (dwMap <= 0) {
		printf("[-] Could not find memory map!\n");
		CloseHandle(hProcess);
		return;
	}

	IPCControl *control = new IPCControl(hProcess, dwMap);
	for (int i = 0; i < control->dwChannelCount; ++i)
		control->channels[i]->PrettyPrint();

	CloseHandle(hProcess);
}

void TriggerIPC(DWORD dwPid)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPid);
	if (hProcess == NULL) {
		printf("[-] Could not open PID %d (err: %d)!\n", dwPid, GetLastError());
		return;
	}

	ServerControl *sc = find_free_servercontrol(hProcess);
	sc->channel->SetState(ChannelState::BUSY);
	CrossCallParams *ccp = new CrossCallParams(sc->channel);
	
	ccp->tag = 62;
	ccp->is_in_out = 0;
	ccp->params_count = 1;

	wchar_t *path = (wchar_t*)L"C:\\testpath\0";
	ccp->parameters[0].buffer = path;
	ccp->parameters[0].size = wcslen(path) * sizeof(wchar_t);
	ccp->parameters[0].type = ArgType::WCHAR_TYPE;
	sc->channel->crosscall = ccp;

	CrossCallReturn *ccr = sc->DoRequest();
	if (ccr->signal_return != 0)
		printf("Signal failed (%08x = %d)\n", ccr->signal_return, ccr->signal_gle);
	else
		ccr->PrettyPrint();

	sc->channel->SetState(ChannelState::FREE);

	delete ccp;
	return;
}

BOOL WINAPI CtrlHandle(DWORD fdwCtrlType)
{
	if (fdwCtrlType == CTRL_C_EVENT) {
		ShouldStop = true;
		return TRUE;
	}

	return FALSE;
}

void Help()
{
	printf("[-] sander: [action] <pid>\n");
	printf("          -m   -  Monitor mode\n");
	printf("          -d   -  Dump channels\n");
	printf("          -t   -  Trigger test call (tag 62)\n");
	printf("          -c   -  Capture IPC traffic and log to disk\n");
	printf("          -h   -  Print this menu\n");
}

int main(int argc, char **argv)
{
	if (argc <= 1 || strcmp(argv[1], "-h") == 0) {
		Help();
		return 1;
	}
	
	SetConsoleCtrlHandler(CtrlHandle, TRUE);

	DWORD dwPid = atoi(argv[2]);
	if (strcmp(argv[1], "-m") == 0) {
		Monitor(dwPid, PRINT_TO_STDOUT);
	}
	else if (strcmp(argv[1], "-d") == 0) {
		Dump(dwPid);
	}
	else if (strcmp(argv[1], "-t") == 0) {
		TriggerIPC(dwPid);
	}
	else if (strcmp(argv[1], "-c") == 0)
	{
		printf("[+] Capturing calls...\n");
		Monitor(dwPid, LOG_TO_FILE);
		printf("[+] %d calls recorded, %d duplicates (%d total)\n", CallCount, CallDup, (CallCount + CallDup));
	}
	else
		printf("[-] Unrecognized option\n");

	return 0;
}
