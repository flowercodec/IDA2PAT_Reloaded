
// ****************************************************************************
// File: Main.cpp
// Desc: IDA2PAT Reloaded plug-in by Sirmabus
//
// ****************************************************************************
#include "stdafx.h"

// Note: Run IDA in plug-in debug mode with -z20

// === Function Prototypes ===
int idaapi IDAP_init();
void idaapi IDAP_term();
bool idaapi IDAP_run(size_t arg);
extern void CORE_Init();
extern void CORE_Process(int iArg);
extern void CORE_Exit();


// === Data ===
char IDAP_comment[] = "IDA2PAT Reloaded: .";
char IDAP_help[] 	= "IDA2PAT Reloaded: .";
char IDAP_name[] 	= "IDA2PAT Reloaded";
char IDAP_hotkey[] 	= "F11"; // Preferred hotkey

// Plug-in description block
extern "C" EXPORT plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
	
	PLUGIN_UNL,				// Plug-in flags
	IDAP_init,	            // Initialization function
	IDAP_term,	            // Clean-up function
	IDAP_run,	            // Main plug-in body
	IDAP_comment,	        // Comment - unused
	IDAP_help,	            // As above - unused
	IDAP_name,	            // Plug-in name shown in Edit->Plugins menu
	IDAP_hotkey	            // Hot key to run the plug-in
};

// Init
int idaapi IDAP_init()
{
    CORE_Init();
    return(PLUGIN_OK);   
}

// Un-init
void idaapi IDAP_term()
{
    CORE_Exit();
}

// Run 
bool idaapi IDAP_run(size_t iArg)
{	
    CORE_Process(iArg);   
	return true;
}



