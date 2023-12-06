#include <Windows.h>
#include <stdio.h>

#define SEED 0xEDB88320
#define STR2 "_CRC32"

unsigned int _crc32h(char* message) {
	int i, crc;
	unsigned int byte, c;
	const unsigned int g0 = SEED, g1 = g0 >> 1,
		g2 = g0 >> 2, g3 = g0 >> 3, g4 = g0 >> 4, g5 = g0 >> 5,
		g6 = (g0 >> 6) ^ g0, g7 = ((g0 >> 6) ^ g0) >> 1;

	i = 0;
	crc = 0xFFFFFFFF;
	while ((byte = message[i]) != 0) {    // Get next byte.
		crc = crc ^ byte;
		c = ((crc << 31 >> 31) & g7) ^ ((crc << 30 >> 31) & g6) ^
			((crc << 29 >> 31) & g5) ^ ((crc << 28 >> 31) & g4) ^
			((crc << 27 >> 31) & g3) ^ ((crc << 26 >> 31) & g2) ^
			((crc << 25 >> 31) & g1) ^ ((crc << 24 >> 31) & g0);
		crc = ((unsigned)crc >> 8) ^ c;
		i = i + 1;
	}
	return ~crc;
}

int main() {

	printf("#define %s%s \t 0x%0.8X \n", "NtAllocateVirtualMemory", STR2, _crc32h("NtAllocateVirtualMemory"));
	printf("#define %s%s \t 0x%0.8X \n", "NtProtectVirtualMemory", STR2, _crc32h("NtProtectVirtualMemory"));
	printf("#define %s%s \t 0x%0.8X \n", "NtCreateThreadEx", STR2, _crc32h("NtCreateThreadEx"));
	printf("#define %s%s \t 0x%0.8X \n", "NtWaitForSingleObject", STR2, _crc32h("NtWaitForSingleObject"));

	getchar();

	return 0;
}