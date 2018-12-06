# MapPE
MapPE constructs the memory mapped image of given PE files.


		  _____ _____  ______\______   \_   _____/
		 /     \__  \ \____ \|     ___/|    __)_ 
		|  Y Y  \/ __ \|  |_> >    |    |        \
		|__|_|  (____  /   __/|____|   /_______  /
		      \/     \/|__|                    \/ 

		Author: Ege Balci
		Github: github.com/egebalci/mappe

		[+] "MZ" magic number found !
		[+] Valid "PE" signature 

		[-------------------------------------]
		[*] ImageBase: 0x400000
		[*] Address Of Entry: 0x4014e0
		[*] Number Of Sections: 7
		[*] Number Of Symbols: 0
		[*] Size Of Image: 36864 bytes
		[*] Size Of Headers: 1024 bytes
		[*] Checksum: 0xb6b9
		[*] Subsystem: 0x3
		[*] Export Table: 0x400000
		[*] Import Table: 0x406000
		[*] Import Address Table: 0x406120
		[-------------------------------------]


		##########################################
		#                                        #
		#   .text    -> 0x401000                 #
		#                                        #
		#                                        #
		#                                        #
		##########################################
		#                                        #
		#   .data    -> 0x403000                 #
		##########################################
		#                                        #
		#   .rdata   -> 0x404000                 #
		##########################################
		#                                        #
		#   .bss     -> 0x405000                 #
		##########################################
		#                                        #
		#   .idata   -> 0x406000                 #
		##########################################
		#                                        #
		#   .CRT     -> 0x407000                 #
		##########################################
		#                                        #
		#   .tls     -> 0x408000                 #
		########################################## -> 0x409000

		[>] Maping PE headers...
		[>] 0x400000
		[>] 0x401000
		[>] Maping sections... 
		[>]  .text
		[>] 0x401000
		[>] 0x403000
		[>]  .data
		[>] 0x403000
		[>] 0x404000
		[>]  .rdata
		[>] 0x404000
		[>] 0x405000
		[>]  .bss
		[>] 0x405000
		[>] 0x406000
		[>]  .idata
		[>] 0x406000
		[>] 0x407000
		[>]  .CRT
		[>] 0x407000
		[>] 0x408000
		[>]  .tls
		[>] 0x408000
		[>] 0x408200

		[+] File mapping completed !

		[*] Starting integrity checks...

		[*] Mapped size: 36864

		[*] Checking image size............................ [OK]
		[*] Checking section alignment..................... [OK]
		[*] Checking data directory intervals.............. [OK]

		[+] Mapped image dumped into Mem.dmp
