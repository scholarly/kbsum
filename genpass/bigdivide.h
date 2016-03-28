/* based on software 

 Copyright (c) 2008 John Graham-Cumming

 (Released under the BSD License)
 See http://www.grc.com/ppp.htm

*/

/*
 Divide an unsigned 128-bit integer by an unsigned integer and return
 the remainder
 */
char bigdivide(char *big, size_t bytes, unsigned int small, unsigned int *remainder);
