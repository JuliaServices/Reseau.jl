#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

typedef int (__cdecl *julia_callback_t)(uintptr_t);

static HANDLE gate;
static HANDLE threads[4];
static struct worker {
    julia_callback_t callback;
    uintptr_t iterations;
} workers[4];
static volatile LONG entered, completed, failed;

/* CreateThread requires WINAPI; Julia's @cfunction uses the separate cdecl callback. */
static DWORD WINAPI thread_main(LPVOID argument)
{
    struct worker *worker = (struct worker *)argument;
    WaitForSingleObject(gate, INFINITE);
    InterlockedIncrement(&entered);
    if (worker->callback(worker->iterations) != 0)
        InterlockedIncrement(&failed);
    InterlockedIncrement(&completed);
    return 0;
}

__declspec(dllexport) DWORD __cdecl start_workers(julia_callback_t callback)
{
    entered = completed = failed = 0;
    gate = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!gate)
        return GetLastError();
    for (int i = 0; i < 4; i++) {
        workers[i].callback = callback;
        /* One adopted thread exits while the others are still unwinding. */
        workers[i].iterations = i == 0 ? 1 : 16;
        threads[i] = CreateThread(NULL, 0, thread_main, &workers[i], 0, NULL);
        if (!threads[i]) {
            DWORD error = GetLastError();
            SetEvent(gate);
            return error;
        }
    }
    SetEvent(gate);
    return 0;
}

__declspec(dllexport) DWORD __cdecl workers_exited(void)
{
    /* Thread handles become signaled after DLL_THREAD_DETACH has finished. */
    return WaitForMultipleObjects(4, threads, TRUE, 0);
}

__declspec(dllexport) int __cdecl finish_workers(void)
{
    int valid = InterlockedCompareExchange(&entered, 0, 0) == 4 &&
                InterlockedCompareExchange(&completed, 0, 0) == 4 &&
                InterlockedCompareExchange(&failed, 0, 0) == 0;
    for (int i = 0; i < 4; i++) {
        CloseHandle(threads[i]);
        threads[i] = NULL;
    }
    CloseHandle(gate);
    gate = NULL;
    return valid;
}
