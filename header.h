/*
 * header.h
 *
 *  Created on: 2013/03/20
 *      Author: hata
 */

#ifndef HEADER_H_
#define HEADER_H_
int AnalyzeIntHeader(char *buff,int  *val);
int AnalyzeCharHeader(char *buff, char *val);
int AnalyzeMethod(char*p,unsigned int *flag);
int AddURI(URI **top,char *hostid,unsigned short hostport);
int DeleteURI(URI **top,char *hostid);
void DisplayURI(int level,URI *uri);
void DisplayPAUTH(PAUTH *pauth);
int AnalyzeCookieHeader(char *buff,COOKIE *cp);
int AnalyzeSetCookieHeader(char *buff,COOKIE *cp);

#endif /* HEADER_H_ */
