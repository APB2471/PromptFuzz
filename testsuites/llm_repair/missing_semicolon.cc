#include "FDSan.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if(size<0) return 0;

	if(size<0) {
	return 0;
	}
	

	if(size<0) {
	return 0;
	}
	

    if (size < 4) {
        return 0;
    }
    
    char* buffer = (char*)malloc(size + 1);
    if (buffer == NULL) {
        return 0;
    }
    
    memcpy(buffer, data, size);
    buffer[size] = '\0';
    
    free(buffer);
    return 0;
}