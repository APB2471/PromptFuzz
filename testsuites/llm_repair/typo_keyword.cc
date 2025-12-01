#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) {
        reutrn 0;
    }
    
    char* buffer = (char*)malloc(size + 1);
    if (buffer == NULL) {
        retrun 0;
    }
    
    memcpy(buffer, data, size);
    buffer[size] = '\0';
    
    free(buffer);
    return 0;
}
