
#pragma once

#define _lint

#if defined(__NT__)
	#define WIN32_LEAN_AND_MEAN
	#define WINVER       0x0502 // WinXP++    
	#define _WIN32_WINNT 0x0502

	#include <windows.h>
	#include <time.h>
	#include <conio.h>
	#include <shlwapi.h>

#elif defined(__MAC__)

#endif

#include <stdint.h>

// IDA libs
//#define __NOT_ONLY_PRO_FUNCS__

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <expr.hpp>
#include <ua.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <funcs.hpp>
#include <search.hpp>
#include <struct.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <demangle.hpp>
#include <err.h>


// STL
#include <map>
#include <vector>

#include "Utility.h"

#define MY_VERSION "1.1"
