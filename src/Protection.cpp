#include "stdafx.h"

/**
 * Signal the given event to report authorization.
 *
 * @param hEvent    Event to signal.
 *
 * @return TRUE.
 */
BOOL
LVModGetAuthorization(HANDLE hEvent)
{
    SetEvent(hEvent);
    return TRUE;
}
