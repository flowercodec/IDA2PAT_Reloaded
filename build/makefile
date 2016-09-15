files=Main.o Core.o Utility.o

include=-I ../src -I ../idasdk/include

libs=-framework IOKit -framework AppKit -msse2 ../idasdk/lib/

CC=g++
strip=strip

CFLAGS=-DNDEBUG -O3 -fno-rtti -fvisibility=hidden -stdlib=libstdc++ -mmacosx-version-min=10.7 -arch i686
IDA64: -DNDEBUG -O3 -fno-rtti -fvisibility=hidden -stdlib=libstdc++ -mmacosx-version-min=10.7

%.o: %.cpp
	$(CC) $(CFLAGS) $(include) -c $< -o $@ 2>> build.log	

IDA2PAT_Reloaded.pmc:$(files) Makefile
	$(CC) -dynamiclib $(CFLAGS) -install_name "@executable_path/IDA2PAT_Reloaded.pmc" $(include) $(files) $(libs) -o IDA2PAT_Reloaded.pmc 2>> build.log
	$(strip) -x IDA2PAT_Reloaded.pmc
IDA64:$(files) Makefile
	$(CC) -dynamiclib $(CFLAGS) -install_name "@executable_path/IDA2PAT_Reloaded.pmc" $(include) $(files) $(libs) -o IDA2PAT_Reloaded.pmc 2>> build.log
	$(strip) -x IDA2PAT_Reloaded.pmc
clean:
	rm -f $(files) *.a *.pmc build.log