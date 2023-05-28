#pragma once
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>

struct module_t
{
   DWORD64 base_addr, size;
};

class memory_manager
{
public:
   module_t target_module;  // Hold target module
   HANDLE target_process; // for target process
   DWORD  pid;      // for target process

   // For getting a handle to a process
   HANDLE get_process(const wchar_t* processName)
   {
      HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
      PROCESSENTRY32 entry;
      entry.dwSize = sizeof(entry);

      do
         if (!_wcsicmp(entry.szExeFile, processName)) {
            pid = entry.th32ProcessID;
            CloseHandle(handle);
            target_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            return target_process;
         }
      while (Process32Next(handle, &entry));

      return nullptr;
   }

   // For getting information about the executing module
   module_t get_target_module(const wchar_t* moduleName) {
      HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
      MODULEENTRY32 mEntry;
      mEntry.dwSize = sizeof(mEntry);

      do {
         if (!_wcsicmp(mEntry.szModule, moduleName)) {
            CloseHandle(hmodule);

            target_module = { (uintptr_t)mEntry.hModule, mEntry.modBaseSize };
            return target_module;
         }
      } while (Module32Next(hmodule, &mEntry));

      module_t mod = { (uintptr_t)false, (uintptr_t)false };
      return mod;
   }

   module_t get_module(const wchar_t* moduleName) {
      HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
      MODULEENTRY32 mEntry;
      module_t mModule;
      mEntry.dwSize = sizeof(mEntry);

      do {
         if (!_wcsicmp(mEntry.szModule, moduleName)) {
            CloseHandle(hmodule);

            mModule = { (uintptr_t)mEntry.hModule, mEntry.modBaseSize };
            return mModule;
         }
      } while (Module32Next(hmodule, &mEntry));

      module_t mod = { (uintptr_t)false, (uintptr_t)false };
      return mod;
   }

   // Basic WPM wrapper, easier to use.
   template <typename var>
   bool write_memory(DWORD64 Address, var Value) {
      return WriteProcessMemory(target_process, (LPVOID)Address, &Value, sizeof(var), 0);
   }

   template <typename var>
   bool write_memory(DWORD64 Address, var Value, DWORD size) {
      return WriteProcessMemory(target_process, (LPVOID)Address, &Value, size, 0);
   }

   // Basic RPM wrapper, easier to use.
   template <typename var>
   var read_memory(DWORD64 Address) {
      var value;
      ReadProcessMemory(target_process, (LPCVOID)Address, &value, sizeof(var), NULL);
      return value;
   }


   // for comparing a region in memory, needed in finding a signature
   bool mem_compare(const BYTE* bData, const BYTE* bMask, const char* szMask) {
      for (; *szMask; ++szMask, ++bData, ++bMask) {
         if (*szMask == 'x' && *bData != *bMask) {
            return false;
         }
      }
      return (*szMask == NULL);
   }

   // for finding a signature/pattern in memory of another process
   uintptr_t signature_scan(DWORD64 start, DWORD64 size, const char* sig, const char* mask)
   {
      BYTE* data = new BYTE[size];
      SIZE_T bytesRead;

      auto MemoryCompare = [](const BYTE* bData, const BYTE* bMask, const char* szMask) {
         for (; *szMask; ++szMask, ++bData, ++bMask) {
            if (*szMask == 'x' && *bData != *bMask) {
               return false;
            }
         }
         return (*szMask == NULL);
      };

      ReadProcessMemory(target_process, (LPVOID)start, data, size, &bytesRead);

      for (DWORD i = 0; i < size; i++)
      {
         if (MemoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask)) {
            delete[] data;
            return start + i;
         }
      }
      delete[] data;
      return NULL;
   }

};
