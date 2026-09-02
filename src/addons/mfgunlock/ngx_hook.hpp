/*
 * Thread-safe Detours installation.
 * SPDX-License-Identifier: MIT
 *
 * Detours rewrites the first bytes of the target function. If another thread's
 * instruction pointer is inside that function at the moment of the rewrite, it
 * resumes mid-instruction -- a hang or a crash, not an error code.
 *
 * DetourUpdateThread is the documented answer: every thread that might be
 * executing the patched code must be registered with the transaction so Detours
 * can suspend it and fix up its instruction pointer. Registering only
 * GetCurrentThread() is correct only when the target is idle, and _nvngx.dll is
 * not idle -- we patch it from the ReShade present callback while the render
 * thread is calling DLSS through it.
 */

#pragma once

#include <windows.h>
#include <tlhelp32.h>

#include <detours.h>

#include <sstream>
#include <tuple>
#include <vector>

#include <include/reshade.hpp>

namespace mfgunlock::hook {

// Function name, storage for the trampoline, replacement.
using HookItem = std::tuple<const char*, void**, void*>;

namespace internal {

// Every thread in this process except the caller.
inline std::vector<HANDLE> OpenOtherThreads() {
  std::vector<HANDLE> threads;
  const DWORD pid = GetCurrentProcessId();
  const DWORD self = GetCurrentThreadId();
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return threads;

  THREADENTRY32 te = {};
  te.dwSize = sizeof(te);
  if (Thread32First(snap, &te)) {
    do {
      if (te.dwSize < FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID)
                          + sizeof(te.th32OwnerProcessID)) {
        continue;
      }
      if (te.th32OwnerProcessID != pid) continue;
      if (te.th32ThreadID == self) continue;
      HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                            FALSE, te.th32ThreadID);
      if (h != nullptr) threads.push_back(h);
    } while (Thread32Next(snap, &te));
  }
  CloseHandle(snap);
  return threads;
}

}  // namespace internal

// Installs `hooks` into `module`. Returns true only if EVERY hook attached and
// the transaction committed -- a partial install leaves some entry points
// patched and others not, which is worse than none.
inline bool Install(HMODULE module, const std::vector<HookItem>& hooks,
                    const char* module_label) {
  if (module == nullptr) return false;

  std::vector<std::pair<void**, void*>> resolved;
  resolved.reserve(hooks.size());
  for (const auto& [name, real, replacement] : hooks) {
    FARPROC proc = GetProcAddress(module, name);
    if (proc == nullptr) {
      std::stringstream s;
      s << "mfgunlock::hook: " << module_label << " has no export " << name
        << " -- not hooking anything in this module.";
      reshade::log::message(reshade::log::level::error, s.str().c_str());
      return false;
    }
    if (*real != nullptr) return false;  // already installed
    *real = reinterpret_cast<void*>(proc);
    resolved.emplace_back(real, replacement);
  }

  if (DetourTransactionBegin() != NO_ERROR) {
    for (auto& [real, unused] : resolved) *real = nullptr;
    return false;
  }

  auto threads = internal::OpenOtherThreads();
  bool threads_ok = true;
  for (HANDLE h : threads) {
    if (DetourUpdateThread(h) != NO_ERROR) threads_ok = false;
  }
  if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) threads_ok = false;

  if (!threads_ok) {
    DetourTransactionAbort();
    for (HANDLE h : threads) CloseHandle(h);
    for (auto& [real, unused] : resolved) *real = nullptr;
    reshade::log::message(
        reshade::log::level::error,
        "mfgunlock::hook: could not register every thread with the Detours "
        "transaction -- refusing to patch, because patching code another thread "
        "is executing hangs the process.");
    return false;
  }

  bool ok = true;
  for (auto& [real, replacement] : resolved) {
    if (DetourAttach(real, replacement) != NO_ERROR) {
      ok = false;
      break;
    }
  }

  if (!ok || DetourTransactionCommit() != NO_ERROR) {
    if (!ok) DetourTransactionAbort();
    for (HANDLE h : threads) CloseHandle(h);
    for (auto& [real, unused] : resolved) *real = nullptr;
    std::stringstream s;
    s << "mfgunlock::hook: failed to install hooks in " << module_label << ".";
    reshade::log::message(reshade::log::level::error, s.str().c_str());
    return false;
  }

  for (HANDLE h : threads) CloseHandle(h);
  std::stringstream s;
  s << "mfgunlock::hook: installed " << resolved.size() << " hook(s) in "
    << module_label << ", with " << threads.size()
    << " other thread(s) registered with the transaction.";
  reshade::log::message(reshade::log::level::info, s.str().c_str());
  return true;
}

// Mirror of Install. Best-effort: used only on process detach.
inline void Uninstall(const std::vector<HookItem>& hooks) {
  if (DetourTransactionBegin() != NO_ERROR) return;
  auto threads = internal::OpenOtherThreads();
  for (HANDLE h : threads) DetourUpdateThread(h);
  DetourUpdateThread(GetCurrentThread());
  for (const auto& [name, real, replacement] : hooks) {
    if (*real != nullptr) DetourDetach(real, replacement);
  }
  if (DetourTransactionCommit() != NO_ERROR) DetourTransactionAbort();
  for (HANDLE h : threads) CloseHandle(h);
}

}  // namespace mfgunlock::hook
