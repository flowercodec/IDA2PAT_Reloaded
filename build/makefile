files=../src/Main.o ../src/Core.o ../src/Utility.o

include=-I ../src -I ../idasdk/include
libs=-framework IOKit -framework AppKit -msse2

CC=g++
strip=strip

CFLAGS=-DNDEBUG -D__MAC__ -D__X64__ -O3 -fno-rtti -fvisibility=hidden -stdlib=libstdc++ -mmacosx-version-min=10.7

ifeq ($(MAKECMDGOALS),IDA32)   
libs+= ../idasdk/ida_dll/libida64.dylib
else ifeq ($(MAKECMDGOALS), IDA64)
CFLAGS+= -D__EA64__
libs+= ../idasdk/ida_dll/libida64.dylib
endif

all:
	@echo "make IDA64 or make IDA32"
	
%.o: %.cpp
	$(CC) $(CFLAGS) $(include) -c $< -o $@ 2>> build.log	

IDA32:clean $(files) Makefile
	$(CC) -dynamiclib $(CFLAGS) -install_name "@executable_path/IDA2PAT_Reloaded.dylib" $(include) $(files) $(libs) -o IDA2PAT_Reloaded.dylib 2>> build.log
	$(strip) -x IDA2PAT_Reloaded.dylib
IDA64:clean $(files) Makefile
	$(CC) -dynamiclib $(CFLAGS) -install_name "@executable_path/IDA2PAT_Reloaded64.dylib" $(include) $(files) $(libs) -o IDA2PAT_Reloaded64.dylib 2>> build.log
	$(strip) -x IDA2PAT_Reloaded64.dylib
clean:
	rm -f $(files) *.a build.log