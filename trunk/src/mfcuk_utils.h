/*
 Package:
    MiFare Classic Universal toolKit (MFCUK)
 
 Package version:
    0.1
 
 Filename:
    mfcuk_utils.h

 Description:
    MFCUK common utility functions prototypes.

 License:
    GPL2 (see below), Copyright (C) 2009, Andrei Costin

 * @file mfcuk_utils.h/
 * @brief 
*/

/*
 VERSION HISTORY
--------------------------------------------------------------------------------
| Number     : 0.1
| dd/mm/yyyy : 23/11/2009
| Author     : zveriu@gmail.com, http://andreicostin.com
| Description: Moved bulk of defines and prototypes from "mfcuk_keyrecovery_darkside.c"
--------------------------------------------------------------------------------
*/

/*
 LICENSE

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 2 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>. 
*/

#ifndef _MFCUK_UTILS_H_
#define _MFCUK_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
    #define NOMINMAX
    #include "windows.h"
    #include "xgetopt.h"
#elif __STDC__
    #include <unistd.h>
    #include <sys/time.h>
    #include <sys/types.h>
#endif

// "Portable" sleep(miliseconds)
#ifdef WIN32
    #define sleep(x) Sleep(x)
#elif __STDC__
    extern struct timeval global_timeout;
    #define sleep(x) { global_timeout.tv_usec = 1000 * (x); select(0,NULL,NULL,NULL,&global_timeout); }
#endif

// "Portable" clear_screen() - NOTE: system performance penalty introduced
#ifdef WIN32
    #define clear_screen()  system("cls")
#elif __STDC__
    #define clear_screen()  system("sh -c clear")
#endif

/**
 * @fn int is_hex(char c)
 * @brief Checks if an ASCII character is a valid hexadecimal base digit
 * @param c The ASCII character to be checked
 * @return Returns true (non-zero) or false (zero)
 *
 * Checks if an ASCII character is a valid hexadecimal base digit.
 * Used for hex2bin() functionality.
 */
int is_hex(char c);

/**
 * @fn unsigned char hex2bin(unsigned char h, unsigned char l)
 * @brief Converts from two nibbles (4 bits) into the corresponding byte
 * @param h The HIGH (left-most in human reading) nibble of two-char hex representation of a byte
 * @param l The LOW (right-most in human reading) nibble of two-char hex representation of a byte
 * @return Returns the byte which is formed from the two-char hex representation of it
 *
 * Converts from two nibbles (4 bits) into the corresponding byte.
 * Uses the algorithm and implementation from here:
 * http://www.velocityreviews.com/forums/t451319-advice-required-on-my-ascii-to-hex-conversion-c.html
 */
unsigned char hex2bin(unsigned char h, unsigned char l);

#endif // _MFCUK_UTILS_H_
