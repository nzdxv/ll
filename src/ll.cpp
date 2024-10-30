#include <functional>
#include <iostream>
#include <memory>
#include <string>

// clang-format off
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#undef WIN32_LEAN_AND_MEAN
// clang-format on

static std::uint32_t process_id(const std::string_view process) {
  PROCESSENTRY32 pe = {};
  pe.dwSize = sizeof(pe);

  std::unique_ptr<void, decltype(&CloseHandle)> snapshot(
      CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle);

  std::uint32_t id{0};
  if (snapshot && Process32First(snapshot.get(), &pe)) {
    do {
      if (process.compare(pe.szExeFile) == 0) {
        id = pe.th32ProcessID;
        break;
      }
    } while (Process32Next(snapshot.get(), &pe));
  }

  return id;
}

static bool load_lib(const std::string_view dll,
                     const std::string_view process) {
  std::uint32_t proc_id{process_id(process)};
  if (!proc_id) {
    std::cerr << "Process '" << process << "' not found.\n";
    return false;
  }

  std::unique_ptr<void, decltype(&CloseHandle)> handle(
      OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id), &CloseHandle);

  std::unique_ptr<void, std::function<void(void *)>> alloc(
      VirtualAllocEx(handle.get(), nullptr, dll.size() + 1,
                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE),
      [handle = handle.get()](void *mem) {
        if (mem)
          VirtualFreeEx(handle, mem, 0, MEM_RELEASE);
      });

  if (!WriteProcessMemory(handle.get(), alloc.get(), dll.data(), dll.size() + 1,
                          nullptr)) {
    std::cerr << "Failed to write dll path to process memory.\n";
    return false;
  }

  const HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
  if (!kernel32 || kernel32 == INVALID_HANDLE_VALUE) {
    std::cerr << "Failed to get handle to kernel32.dll.\n";
    return false;
  }

  const FARPROC loadlib = GetProcAddress(kernel32, "LoadLibraryA");
  if (!loadlib) {
    std::cerr << "Failed to find LoadLibraryA address.\n";
    return false;
  }

  std::unique_ptr<void, decltype(&CloseHandle)> thread(
      CreateRemoteThread(handle.get(), nullptr, 0,
                         reinterpret_cast<LPTHREAD_START_ROUTINE>(loadlib),
                         alloc.get(), 0, nullptr),
      &CloseHandle);
  if (!thread) {
    std::cerr << "Failed to create remote thread.\n";
    return false;
  }

  WaitForSingleObject(thread.get(), INFINITE);

  return true;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: ll <DLL_PATH> <PROCESS_NAME>\n";
    return -1;
  }

  const std::string dll_name = argv[1];
  const std::string proc_name = argv[2];

  char dll_path[MAX_PATH];
  std::uint32_t length =
      GetFullPathName(dll_name.data(), MAX_PATH, dll_path, nullptr);
  if (!length || length > MAX_PATH) {
    std::cerr << "Error resolving dll path.\n";
    return -2;
  }

  if (!load_lib(dll_path, proc_name)) {
    return -3;
  }

  return 0;
}
