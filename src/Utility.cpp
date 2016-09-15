
// ****************************************************************************
// File: Utility.cpp
// Desc: Utility functions
//
// ****************************************************************************
#include "stdafx.h"

#ifdef __MAC__
namespace MacMarch {
	#include <mach/mach_time.h>
}
#endif

// ****************************************************************************
// Func: GetTimeSamp()
// Desc: Get elapsed factional seconds
//
// ****************************************************************************
ALIGN(32) TIMESTAMP GetTimeStamp() 
{
#if defined(__NT__)
	LARGE_INTEGER tLarge;
	QueryPerformanceCounter(&tLarge);
	static ALIGN(16) TIMESTAMP s_ClockFreq;
	if(s_ClockFreq == 0.0)
	{
		LARGE_INTEGER tLarge;
		QueryPerformanceFrequency(&tLarge);
		s_ClockFreq = (TIMESTAMP) tLarge.QuadPart; 
	}
	return((TIMESTAMP) tLarge.QuadPart / s_ClockFreq);
#elif defined(__MAC__)
	MacMarch::mach_timebase_info_data_t timebase;
	MacMarch::mach_timebase_info(&timebase);
	uint64_t ts = MacMarch::mach_absolute_time();
	return (TIMESTAMP)ts * (double)timebase.numer /
		(double)timebase.denom /1e9;
#endif
}


// ****************************************************************************
// Func: Log()
// Desc: Send text to a log file.
//
// ****************************************************************************
ALIGN(32) void Log(FILE *pLogFile, const char *format, ...)
{
	if(pLogFile && format)
	{
		// Format string
		va_list vl;
        char	str[2048] = {0};

		va_start(vl, format);
		qsnprintf(str, (sizeof(str) - 1), format, vl);
		va_end(vl);

		// Out to file
		qfputs(str, pLogFile);
        qflush(pLogFile);
	}
}

// Common hash type
ALIGN(32) uint32_t DJBHash(const uint8_t *pData, int iSize)
{
	register uint32_t uHash = 5381;

	for(int i = 0; i < iSize; i++)
	{
		uHash = (((uHash << 5) + uHash) + (uint32_t) *pData);
		pData++;
	}

	return(uHash);
}

// Faster?
// http://www.ccsinfo.com/forum/viewtopic.php?t=24977


ALIGN(32) uint16_t GetCRC16(uint8_t* pData, int iLen)
{
	if(pData && iLen)
	{
		static const ALIGN(16) uint aCRC_CCITT_TABLE[256] =
		{
			0x00000000, 0x00001189, 0x00002312, 0x0000329B, 0x00004624, 0x000057AD, 0x00006536, 0x000074BF, 
			0x00008C48, 0x00009DC1, 0x0000AF5A, 0x0000BED3, 0x0000CA6C, 0x0000DBE5, 0x0000E97E, 0x0000F8F7, 
			0x00001081, 0x00000108, 0x00003393, 0x0000221A, 0x000056A5, 0x0000472C, 0x000075B7, 0x0000643E, 
			0x00009CC9, 0x00008D40, 0x0000BFDB, 0x0000AE52, 0x0000DAED, 0x0000CB64, 0x0000F9FF, 0x0000E876, 
			0x00002102, 0x0000308B, 0x00000210, 0x00001399, 0x00006726, 0x000076AF, 0x00004434, 0x000055BD, 
			0x0000AD4A, 0x0000BCC3, 0x00008E58, 0x00009FD1, 0x0000EB6E, 0x0000FAE7, 0x0000C87C, 0x0000D9F5, 
			0x00003183, 0x0000200A, 0x00001291, 0x00000318, 0x000077A7, 0x0000662E, 0x000054B5, 0x0000453C, 
			0x0000BDCB, 0x0000AC42, 0x00009ED9, 0x00008F50, 0x0000FBEF, 0x0000EA66, 0x0000D8FD, 0x0000C974, 
			0x00004204, 0x0000538D, 0x00006116, 0x0000709F, 0x00000420, 0x000015A9, 0x00002732, 0x000036BB, 
			0x0000CE4C, 0x0000DFC5, 0x0000ED5E, 0x0000FCD7, 0x00008868, 0x000099E1, 0x0000AB7A, 0x0000BAF3, 
			0x00005285, 0x0000430C, 0x00007197, 0x0000601E, 0x000014A1, 0x00000528, 0x000037B3, 0x0000263A, 
			0x0000DECD, 0x0000CF44, 0x0000FDDF, 0x0000EC56, 0x000098E9, 0x00008960, 0x0000BBFB, 0x0000AA72,
			0x00006306, 0x0000728F, 0x00004014, 0x0000519D, 0x00002522, 0x000034AB, 0x00000630, 0x000017B9, 
			0x0000EF4E, 0x0000FEC7, 0x0000CC5C, 0x0000DDD5, 0x0000A96A, 0x0000B8E3, 0x00008A78, 0x00009BF1, 
			0x00007387, 0x0000620E, 0x00005095, 0x0000411C, 0x000035A3, 0x0000242A, 0x000016B1, 0x00000738, 
			0x0000FFCF, 0x0000EE46, 0x0000DCDD, 0x0000CD54, 0x0000B9EB, 0x0000A862, 0x00009AF9, 0x00008B70, 
			0x00008408, 0x00009581, 0x0000A71A, 0x0000B693, 0x0000C22C, 0x0000D3A5, 0x0000E13E, 0x0000F0B7, 
			0x00000840, 0x000019C9, 0x00002B52, 0x00003ADB, 0x00004E64, 0x00005FED, 0x00006D76, 0x00007CFF, 
			0x00009489, 0x00008500, 0x0000B79B, 0x0000A612, 0x0000D2AD, 0x0000C324, 0x0000F1BF, 0x0000E036, 
			0x000018C1, 0x00000948, 0x00003BD3, 0x00002A5A, 0x00005EE5, 0x00004F6C, 0x00007DF7, 0x00006C7E, 
			0x0000A50A, 0x0000B483, 0x00008618, 0x00009791, 0x0000E32E, 0x0000F2A7, 0x0000C03C, 0x0000D1B5, 
			0x00002942, 0x000038CB, 0x00000A50, 0x00001BD9, 0x00006F66, 0x00007EEF, 0x00004C74, 0x00005DFD, 
			0x0000B58B, 0x0000A402, 0x00009699, 0x00008710, 0x0000F3AF, 0x0000E226, 0x0000D0BD, 0x0000C134, 
			0x000039C3, 0x0000284A, 0x00001AD1, 0x00000B58, 0x00007FE7, 0x00006E6E, 0x00005CF5, 0x00004D7C, 
			0x0000C60C, 0x0000D785, 0x0000E51E, 0x0000F497, 0x00008028, 0x000091A1, 0x0000A33A, 0x0000B2B3, 
			0x00004A44, 0x00005BCD, 0x00006956, 0x000078DF, 0x00000C60, 0x00001DE9, 0x00002F72, 0x00003EFB, 
			0x0000D68D, 0x0000C704, 0x0000F59F, 0x0000E416, 0x000090A9, 0x00008120, 0x0000B3BB, 0x0000A232, 
			0x00005AC5, 0x00004B4C, 0x000079D7, 0x0000685E, 0x00001CE1, 0x00000D68, 0x00003FF3, 0x00002E7A, 
			0x0000E70E, 0x0000F687, 0x0000C41C, 0x0000D595, 0x0000A12A, 0x0000B0A3, 0x00008238, 0x000093B1, 
			0x00006B46, 0x00007ACF, 0x00004854, 0x000059DD, 0x00002D62, 0x00003CEB, 0x00000E70, 0x00001FF9, 
			0x0000F78F, 0x0000E606, 0x0000D49D, 0x0000C514, 0x0000B1AB, 0x0000A022, 0x000092B9, 0x00008330, 
			0x00007BC7, 0x00006A4E, 0x000058D5, 0x0000495C, 0x00003DE3, 0x00002C6A, 0x00001EF1, 0x00000F78
		};

		uint32_t uData;
		uint32_t uCRC = 0xFFFF;

		do
		{
			uData = (uint32_t) *pData++;
			uCRC = ((uCRC >> 8) ^ aCRC_CCITT_TABLE[((uCRC ^ uData) & 0xFF)]);

		}while(--iLen);

		uCRC = ~uCRC;
		uData = uCRC;
		uCRC = (uCRC << 8) | ((uData >> 8) & 0xFF);

		return((uint16_t) uCRC);
	}

	return(0);
}

bool FileExists(char* path)
{
#if defined(__NT__)
	return PathFileExistsA(path);
#elif defined(__MAC__)
	int res = access(path, R_OK);
	if (res < 0) {
		if (errno == ENOENT) {
			return false;
		} else {
			return true;
		}
	}
#endif
}
