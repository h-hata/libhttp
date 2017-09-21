/*
 * util.h
 *
 *  Created on: 2013/03/20
 *      Author: hata
 */

#ifndef UTIL_H_
#define UTIL_H_
void EncodeEscapeString(char *pinp,char *poutp);
void TrimChar(char *ptr,char c);
char *SkipChars(char *ptr,char c);
char *SeparateLex1(char *buff,char c,char *optr,int *plen);
int SeparateLex(char *buff,char c,char **optr,int n);
PACKET *AllocPacket(void);
void FreePacket(PACKET *msg);


#endif /* UTIL_H_ */
