/*
 *  hexString.h
 *  byteutils
 *
 *  Created by Richard Murphy on 3/7/10.
 *  Copyright 2010 McKenzie-Murphy. All rights reserved.
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus 
extern "C" {
#endif
uint8_t *hexStringToBytes(char *inhex);
char *bytesToHexString(uint8_t *bytes, size_t buflen);
#ifdef __cplusplus 
}
#endif
