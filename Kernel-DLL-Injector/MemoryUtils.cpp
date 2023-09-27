#include "MemoryUtils.hpp"

// Constructor for memory utils class, that takes callbacks and pid
MemoryUtils::MemoryUtils(OperationCallback operation, uint64_t pid)
{
	operationCallback = operation;
	processId = pid;
}

// Function to read a buffer of memory from the target process
NTSTATUS MemoryUtils::ReadBuffer(uint64_t address, LPVOID lpBuffer, SIZE_T nSize)
{
	// Check if the lpbuffer value is valid (NOT NULL)
	if (lpBuffer == 0)
		return STATUS_INVALID_PARAMETER;

	// This function reads memory from the current process into the target buffer
	return Communication::CopyVirtualMemory(operationCallback, processId, address, GetCurrentProcessId(), uintptr_t(lpBuffer), nSize);
}

NTSTATUS MemoryUtils::WriteMemory(uint64_t address, uintptr_t dstAddress, SIZE_T nSize)
{
	// Check if the destination address is valid not null
	if (dstAddress == 0)
		return STATUS_INVALID_PARAMETER;

	// This function write memory from our current process into our target process
	return Communication::CopyVirtualMemory(operationCallback, GetCurrentProcessId(), dstAddress, processId, address, nSize);
}
// A function to read a chain of memory addresses in the target process
uint64_t MemoryUtils::ReadChain(uint64_t base, const std::vector<uint64_t>& offsets)
{
	// Start with a base address and follow a chain offsets down to the final address
	uint64_t result = Read<uint64_t>(base + offsets.at(0));

	for (int i = 1; i < offsets.size(); i++)
		result = Read<uint64_t>(result + offsets.at(i));

	// Return our final result
	return result;
}

// Function to get the address of a base module in the target process
uint64_t MemoryUtils::GetModuleBase(wstring moduleName)
{
	// Use this function to do it
	return Communication::GetModuleBaseOperation(operationCallback, processId, moduleName);
}

// Function to read a Unicode String from the target process and turn it into a UTF-8 String
string MemoryUtils::GetUnicodeString(uint64_t address, int strLength)
{
	char16_t wcharTmp[64] = { '\0' };
	ReadBuffer(address, wcharTmp, strLength * 2);

	// Convert UTF-16 string into UTF-8 String
	std::string utfStr = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>{}.to_bytes(wcharTmp);

	return utfStr;
}

// Function to allocate memory in the target process 
uint64_t MemoryUtils::AllocateMemory(size_t size, uint32_t allocation_type, uint32_t protect)
{
	uint64_t address = 0; // NULL

	// Function to allocate Memory
	return Communication::AllocateVirtualMemory(operationCallback, processId, size, allocation_type, protect, address);
}

// Function to change the protection of memory in a target process
NTSTATUS MemoryUtils::ProtectMemory(uint64_t address, size_t size, uint32_t protect)
{
	return Communication::ProtectVirtualMemory(operationCallback, processId, size, protect, address);
}

// Function to free memory in a target process
NTSTATUS MemoryUtils::FreeMemory(uint64_t address)
{
	return Communication::FreeVirtualMemory(operationCallback, processId, address);
}
