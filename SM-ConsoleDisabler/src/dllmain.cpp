#include <Windows.h>
#include <iostream>
#include <array>

constexpr auto CONSOLE_PTR = 0x127D668;
static void LogReplacement(const std::string& message, WORD colour, DWORD type) {}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hModule);

		const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
		void* console = *reinterpret_cast<void**>(base + CONSOLE_PTR);
		void** vtable = *reinterpret_cast<void***>(console);

		DWORD oldProtect;
		VirtualProtect(&vtable[1], 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);

		// At  0x0 (0) is the virtual destructor
		// At  0x8 (1) is the virtual function Log
		// At 0x10 (2) is the virtual function LogNoReturn (only logs a message once)
		vtable[1] = reinterpret_cast<void*>(&LogReplacement);
		vtable[2] = reinterpret_cast<void*>(&LogReplacement);

		// At ScrapMechanic.exe+2D7BA8 is an if statement jump out clause, we want to change jz to jmp so that it never allocates a console

		// new bytes:
		// ScrapMechanic.exe+2D7BA8 - E9 B3000000           - jmp ScrapMechanic.exe+2D7C60
		// ScrapMechanic.exe+2D7BAD - 90                    - nop 
		constexpr std::array<uint8_t, 6> newBytes = { 0xE9, 0xB3, 0x00, 0x00, 0x00, 0x90 };
		memcpy_s(reinterpret_cast<void*>(base + 0x2D7BA8), newBytes.size(), newBytes.data(), newBytes.size());

		// Check if a console is already allocated, if so, free it
		HANDLE hConsole = *reinterpret_cast<HANDLE*>(reinterpret_cast<uintptr_t>(console) + 0x58);
		if (hConsole != INVALID_HANDLE_VALUE)
			FreeConsole();

		VirtualProtect(&vtable[1], 0x10, oldProtect, &oldProtect);
	}

	return TRUE;
}
