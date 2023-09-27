#include "Communication.hpp"

// Initialize the Communication Module by loading a DLL
// Returns a function pointer to an operation within the loaded DLL
OperationCallback Communication::Init(string moduleName, string exportName)
{
	// Load the Dynamic Lib
	auto hModule = LoadLibraryA(moduleName.c_str());

	if (!hModule)
	{
		// If loading fails, print an error message and return nullptr
		printf(xor ("[-] Communication init error: Failed to load library.\n"));
		return nullptr;
	}

	// Get a function pointer to a specified export within the loaded DLL
	OperationCallback callback = (OperationCallback)GetProcAddress(hModule, exportName.c_str());

	if (!callback)
	{
		// If the export is not found print an error and return nullptr
		printf(xor ("[-] Communication init error: Export not found.\n"));
		return nullptr;
	}

	// Return the function pointer to the caller
	return callback;
}

// Test an operation using the provided callback function 
bool Communication::TestOperation(OperationCallback operation)
{
	// Create a packet for communication 
	PACKET_BASE packet{};
	packet.op = TEST;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	// Set up a Vectored Exception Handler to continue execution after exception
	constexpr ULONG firstCall = 1;
	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	// Call the operation callback with specific parameters
	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		// If the operation fails, print an error message and return false
		printf(xor ("[+] Test operation failed.\n"));
		return false;
	}

	// Remove the veh
	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	// Return the result of the test
	return packet.client.test.valid;
}

// Copy virtual memory from one process to another
NTSTATUS Communication::CopyVirtualMemory(OperationCallback operation, ULONGLONG srcPid, uintptr_t srcAddr, ULONGLONG targetPid, uintptr_t targetAddr, SIZE_T size)
{	
	// set up our packet 
	PACKET_BASE packet{};
	packet.op = COPY_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	// Populate a server-side request structure 
	auto& serverRequest = packet.server.copy_virtual_memory;
	serverRequest.sourcePid = srcPid;
	serverRequest.sourceAddress = srcAddr;
	serverRequest.targetPid = targetPid;
	serverRequest.targetAddress = targetAddr;
	serverRequest.size = size;

	// Set up a veh to continue execute after an exception
	constexpr ULONG firstCall = 1;
	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	// Call the operatiob callback with specific parameters 
	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		//printf(xor ("[+] Copy virtual memory operation failed.\n"));
		// If the operation fails, return an error status 
		return STATUS_INVALID_HANDLE;
	}

	// Remove the veh
	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	// Receive the result from the client side response
	auto clientRequest = packet.client.copy_virtual_memory;

	// Return the result statuws 
	return NTSTATUS(clientRequest.size);
}

// Function to get the base address of a module in a target process
uint64_t Communication::GetModuleBaseOperation(OperationCallback operation, ULONGLONG processId, wstring moduleName)
{
	// Set up our packet
	PACKET_BASE packet{};
	packet.op = GET_MODULE_BASE_SIZE;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	// Create a server-side request structure
	auto& serverRequest = packet.server;
	moduleName.copy(serverRequest.get_module.name, moduleName.length());
	serverRequest.get_module.pid = processId;

	// Sety up VEH
	constexpr ULONG firstCall = 1;
	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	// Call the operation callback with specific parameters
	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		printf(xor ("[+] Get module base operation failed.\n"));
		return -1;
	}

	// Remove VEH
	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	// Get the result from the client side response
	auto clientRequest = packet.client.get_module;

	// Return the base address 
	return clientRequest.baseAddress;
}

// Allocate Virtual Memory Function
uint64_t Communication::AllocateVirtualMemory(OperationCallback operation, ULONGLONG targetPid, size_t size, uint32_t allocationType, uint32_t protect, uintptr_t sourceAddress)
{
	// Set up packet fields
	PACKET_BASE packet{};
	packet.op = ALLOC_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	// Set up a Server-side request structure 
	auto& serverRequest = packet.server.alloc_virtual_memory;
	serverRequest.targetPid = targetPid;
	serverRequest.sourceAddress = sourceAddress;
	serverRequest.allocationType = allocationType;
	serverRequest.protect = protect;
	serverRequest.size = size;
	serverRequest.code = STATUS_INTERRUPTED;

	// Create a VEH to handle exceptions
	constexpr ULONG firstCall = 1;
	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	// Perform the operation using the using the provided callback
	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		// If there is an error print an error and exit
		printf(xor ("[+] Allocate virtual memory operation failed.\n"));
		return -1;
	}

	// Remove VEH
	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	// Get result from client side
	auto clientRequest = packet.client.alloc_virtual_memory;

	// Return result
	return clientRequest.targetAddress;
}

// Function to protect virtual memory
NTSTATUS Communication::ProtectVirtualMemory(OperationCallback operation, ULONGLONG targetPid, size_t size, uint32_t protect, uintptr_t sourceAddress)
{
	// Set up packet fields
	PACKET_BASE packet{};
	packet.op = PROTECT_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	// Set up server side request structure 
	auto& serverRequest = packet.server.protect_virtual_memory;
	serverRequest.targetPid = targetPid;
	serverRequest.sourceAddress = sourceAddress;
	serverRequest.protect = protect;
	serverRequest.size = size;
	serverRequest.code = STATUS_INTERRUPTED;

	// Create VEH
	constexpr ULONG firstCall = 1;
	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	// Perform the operation using the specific/provided callback
	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		// If fail then print error code and then exit
		printf(xor ("[+] Protect virtual memory operation failed.\n"));
		return -1;
	}

	// Remove VEH
	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	// Extract the client request from the packet and return the status code >?>?>
	
	// Get Result from Client Side
	auto clientRequest = packet.client.protect_virtual_memory;

	// Protect
	protect = clientRequest.protect;

	// Return Status Code
	return NTSTATUS(clientRequest.code);
}

// Function to Free Virtual Memory
NTSTATUS Communication::FreeVirtualMemory(OperationCallback operation, ULONGLONG targetPid, uintptr_t address)
{
	// Set up packet fields
	PACKET_BASE packet{};
	packet.op = FREE_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	// Set up server-side request structure
	auto& serverRequest = packet.server.free_memory;
	serverRequest.targetPid = targetPid;
	serverRequest.address = address;
	serverRequest.code = STATUS_INTERRUPTED;

	// Create VEH
	constexpr ULONG firstCall = 1;
	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	// Conduct operation with specified Parameters
	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		// If it fails then print an error code and exit 
		printf(xor ("[+] Free virtual memory operation failed.\n"));
		return -1;
	}

	// Remove VEH
	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	// Extract client request from the client side
	auto clientRequest = packet.client.free_memory;

	// Return the client request's status code
	return NTSTATUS(clientRequest.code);
}
