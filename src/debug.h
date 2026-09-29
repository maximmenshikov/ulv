#ifndef DEBUG_H
#define DEBUG_H

//#define DEBUG_ENABLED

#ifdef DEBUG_ENABLED
#define DEBUGLOG 1
#else
#define DEBUGLOG 0
#define RETAILMSG(a, b)
#endif
#endif
