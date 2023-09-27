#include "ProcessUtils.hpp"

#include <TlHelp32.h>

// Get the PID from our ProcessName
DWORD ProcessUtils::GetProcessID(string processName)
{
	// If we get an empty value from the Human Component
	if (processName.empty())
		return NULL;

	// Take a Snapshot of the process list
	// The function creates a snapshot of the systems current processes
	// TH32CS_SNAPPROCESS specifies that we want to capture the process list
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	// If we receive an INVALID_HANDLE_VALUE 
	// that means there is an issue with creating the SNAPSHOT/capturing the processes
	if (hSnap == INVALID_HANDLE_VALUE)
		return NULL;

	// Create a structure to hold info about a process in the snapshot
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe); // Set the size of the structure to nsure compatibility

	// Start iterating the through the list of processes
	if (Process32First(hSnap, &pe))
	{
		// Iterate throiugh the process list
		while (Process32Next(hSnap, &pe))
		{
			// Check if the process name matches the provided processname
			if (!strcmp(pe.szExeFile, processName.c_str()))
			{
				// If a matching handle is found close the handle and 
				// return the pid
				CloseHandle(hSnap);
				return pe.th32ProcessID;
			}
		}
	}

	// Close the handle whether the handle was found or not
	CloseHandle(hSnap);

	return NULL;
}
