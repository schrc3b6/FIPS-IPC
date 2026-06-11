/**
 *  Functions for converting binary IP addresses in network byte order
 *  to string representation
 * 
 * 
*/
#pragma once

#ifndef _IP_TO_STR_H
#define _IP_TO_STR_H
#include <stdint.h>

/**
 * Converts IPv4 address at src to string and copies it to dst.
 * Returns the length of the string written to dst
 * 
 * */ 

uint8_t ipv4_to_str(uint32_t * src, char * dst);

/**
 * Converts IPv6 address at src to string and copies it to dst.
 * Returns the length of the string written to dst
 * 
 * */

uint8_t ipv6_to_str(__uint128_t * src, char * dst);

/**
 * Converts IPv4 address at src to string and copies it to dst.
 * Attemps to shorten address representation by replacing zeros if possible
 * Returns the length of the string written to dst
 * 
 * WARNING! This function is not tested and probably not functioning as expected
 * */
uint8_t ipv6_to_str_fancy(__uint128_t * src, char * dst);

#endif
