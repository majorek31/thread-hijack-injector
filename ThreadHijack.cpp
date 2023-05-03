#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

DWORD GetProcessID(const char* name);
DWORD GetThreadID(DWORD pid);
bool HijackInjection(DWORD pid, const char* dll);

int main(int argc, const char** argv)
{
	if (argc < 3) {
		printf("usage: loader.exe process dllpath\n");
		return -1;
	}
	DWORD pid = GetProcessID(argv[1]);
	if (!pid) {
		printf("Process is not running!\n");
		return -1;
	}
	DWORD tid = GetThreadID(pid);
	if (!tid) {
		printf("Cannot connect to thread!\n");
		return -1;
	}
	printf("process found %d\nHijacking %d\n", pid, tid);
	HijackInjection(pid, "C:\\Dev\\HijackTargets\\Debug\\HijackTargets.dll");

}
bool HijackInjection(DWORD pid, const char* dll) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, GetThreadID(pid));
	if (!(hProcess && hThread))
		return false;
	SuspendThread(hThread);
	CONTEXT ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ctx);
	DWORD returnAddress = ctx.Eip;
	byte shellcode[20] = {
		0x50, // push eax
		0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
		0x68, 0x00, 0x00, 0x00, 0x00, // push 0
		0xFF, 0xD0, // call eax
		0x58, // pop eax
		0x68, 0x00, 0x00, 0x00, 0x00, // push 0
		0xC3, // ret
	};
	void* allocatedName = VirtualAllocEx(hProcess, 0, strlen(dll), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!allocatedName)
		return false;
	WriteProcessMemory(hProcess, allocatedName, dll, strlen(dll), 0);
	*(DWORD*)(shellcode + 0x2) = (DWORD)LoadLibraryA;
	*(DWORD*)(shellcode + 0x7) = (DWORD)allocatedName;
	*(DWORD*)(shellcode + 0xF) = (DWORD)returnAddress;
	void* allocatedShellcode = VirtualAllocEx(hProcess, 0, 20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, allocatedShellcode, shellcode, 20, 0);
	ctx.Eip = (DWORD)allocatedShellcode;
	SetThreadContext(hThread, &ctx);
	ResumeThread(hThread);
}

DWORD GetThreadID(DWORD pid) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 entry;
	memset(&entry, 0, sizeof(entry));
	entry.dwSize = sizeof(entry);
	Thread32First(hSnap, &entry);
	do
	{
		if (entry.th32OwnerProcessID == pid) {
			CloseHandle(hSnap);
			return entry.th32ThreadID;
		}
	} while (Thread32Next(hSnap, &entry));
	CloseHandle(hSnap);
}

DWORD GetProcessID(const char* name) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry;
	memset(&entry, 0, sizeof(entry));
	entry.dwSize = sizeof(entry);
	Process32First(hSnap, &entry);
	do
	{
		if (!strcmp(name, entry.szExeFile)) {
			CloseHandle(hSnap);
			return entry.th32ProcessID;
		}
	} while (Process32Next(hSnap, &entry));
	CloseHandle(hSnap);
	return 0;
}