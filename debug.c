/*
 * debug.c
 *
 *  Created on: 2013/05/06
 *      Author: hata
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "http.h"
#include "parser.h"
#include "util.h"


void DispCookie(COOKIE *cp)
{
	COOKIE_AV	*av;
	int i=1;
	for(;cp;cp=cp->next){
		printf("No.%d\n",i++);
		for(av=cp->av;av;av=av->next){
			printf("\tAV %s=%s\n",av->attr,av->value);
		}
	}
}


void DispPkt(PACKET *pkt)
{
	printf("type:%s %d\n",(pkt->start.type==1 ? "REQUEST(1)" : "RESPONSE(2)"),pkt->start.type);
	printf("message:%d\n",pkt->start.message);
	printf("method:%s\n",pkt->start.method);
	printf("url:%s\n",pkt->start.url);
	printf("proto:%s\n",pkt->start.proto);
	printf("ver:%d\n",pkt->start.ver);
	printf("code:%d\n",pkt->start.code);
	printf("response:%s\n",pkt->start.response);

	printf("Header\n--------------------\n%s",pkt->received_header);

	printf("ELSE_H\n--------------------\n%s",pkt->header.general);
	if(pkt->contents_len){
		char *ptr=malloc(pkt->contents_len+1);
		if(ptr){
			memset(ptr,0,pkt->contents_len+1);
			memcpy(ptr,pkt->contents,pkt->contents_len);
			printf("Bodylen:%d\n",pkt->contents_len);
			printf("%s\n",ptr);
			free(ptr);
		}
	}
	printf("Location:%s\n",pkt->header.location);
	printf("Cookie\n");
	DispCookie(pkt->header.cookie);
	printf("Cookie2\n");
	DispCookie(pkt->header.cookie2);
	printf("SetCookie\n");
	DispCookie(pkt->header.setcookie);
	printf("SetCookie2\n");
	DispCookie(pkt->header.setcookie2);
}

