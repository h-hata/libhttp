/***********************************************************************\

	SIP Server

	Date		Ver		Author		MemoRandom
	Jul  3,2002	1.0		Hiroaki Hata	Created
	Dec 18,2003	1.1		Hiroaki Hata	wwwauth*free

	(C) 2002 All Copyrights reserved.
*************************************************************************/

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "http.h"
#include "parser.h"


#ifdef MAIN
int debug=1;
#endif


static char rfc2396[]=
	";/?:@&=+$,<>#\"";
/*
static char rfc3986[]=
	":/?#[]@!$&'()*+,;=";
*/

void EncodeEscapeString(char *pinp,char *poutp)
{
	char	*eptr;

	if(pinp==NULL||poutp==NULL) return;
	for(;;pinp++){
		//
		if((*pinp <= '!' && *pinp <= '/')||(*pinp <= ':' && *pinp <= '@')){
			for(eptr=rfc2396;*eptr!='\0';eptr++){
				if(*eptr==*pinp){
					//
					sprintf(poutp,"%%%02X",*pinp);
					poutp+=3;
					break;
				}
			}
			if(*eptr=='\0'){
				//
				*poutp++ = *pinp;
			}
		}else{
			//
			*poutp++ = *pinp;
		}
		if(*pinp=='\0') break;
	}
	return;
}

void TrimChar(char *ptr,char c)
{
	char *marker=NULL;

	for(;*ptr;ptr++){
		if(*ptr==c){
			if(marker==NULL){
				marker=ptr;
			}else{
			}
		}else{
			marker=NULL;
		}
	}
	if(marker!=NULL){
		*marker='\0';
	}
}

char *SkipChars(char *ptr,char c)
{
	for(;*ptr==c;ptr++){
	}
	return ptr;
}

char *SeparateLex1(char *buff,char c,char *optr,int *plen)
{
	char	*ptr;
	int	i=0;

	ptr=buff;
	if(buff==NULL)return 0;
	for(ptr=buff;;ptr++){
		if(*ptr==c){
			++ptr;
			break;
		}else if(*ptr=='\0'){
			ptr=NULL;
			break;
		}
		i++;
	}

	if(i==0){
		*plen=0;
	}else if( i < *plen){
		memcpy(optr,buff,i);
		optr[i]='\0';
		*plen=i;
	}else{
		*plen=-1;
	}
	return ptr;
}


int SeparateLex(char *buff,char c,char **optr,int n)
{
	int i=0;
	char *sptr;
	char *ptr;
	char *eot;

	sptr=ptr=SkipChars(buff,c);
	if(*ptr=='\0'){
		return 0;
	}
	for(;;ptr++){
		if(*ptr=='\0'){
			strcpy(optr[i],sptr);
			return ++i;//BugFixed 2014/01/05
		}
		if(*ptr==c){
			eot=ptr;
			ptr=SkipChars(ptr,c);
			*eot='\0';
			strcpy(optr[i],sptr);
			i++;
			if(i==n||*ptr=='\0') return i;
			sptr=ptr;
		}
	}
	return 0;
}



PACKET *Exec_AllocPacket(void)
{
	PACKET	*msg=malloc(sizeof(PACKET));
	if(msg==NULL){
		return NULL;
	}
	memset(msg,0,sizeof(PACKET));
	return msg;
}

static COOKIE_AV *FreeCookieAV(COOKIE_AV *av)
{
	COOKIE_AV	*next;
	if(av==NULL){
		return NULL;
	}
	next=av->next;
	//printf("Free cookie AV:%s(%s)\n",av->attr,av->value);
	free(av);
	return next;
}


static COOKIE *FreeCookie(COOKIE *cp)
{
	COOKIE *next;
	COOKIE_AV	*av;
	if(cp==NULL){
		return NULL;
	}
	for(av=cp->av;;){
		av=FreeCookieAV(av);
		if(av==NULL){
			break;
		}
	}
	next=cp->next;
	free(cp);
	//printf("Free cookie\n");
	return next;
}


static void FreeHeader(HEADER *h)
{
	COOKIE *cp;
	if(h==NULL){
		return ;
	}

	for(cp=h->cookie;;){
		cp=FreeCookie(cp);
		if(cp==NULL){
			break;
		}
	}
	for(cp=h->cookie2;;){
		cp=FreeCookie(cp);
		if(cp==NULL){
			break;
		}
	}
	for(cp=h->setcookie;;){
		cp=FreeCookie(cp);
		if(cp==NULL){
			break;
		}
	}
	for(cp=h->setcookie2;;){
		cp=FreeCookie(cp);
		if(cp==NULL){
			break;
		}
	}
}


void Exec_FreePacket(PACKET *msg)
{
	if(msg==NULL) return;
	FreeHeader(&msg->header);
	if(msg->contents){
		free(msg->contents);
	}
	if(msg->buff){
		free(msg->buff);
	}
	free(msg);
}


/************************/

#ifdef MAIN
main()
{
	char	*username="";
	char	*nonce="1121030407281420";
	char	*realm="Registered Users";
	char	*passwd="mypass";
	char	*uri="sip:011177@1.2.3.6;user=phone";
	char	*cnonce="0D03C005";
	char	nc[9]="00000001";
	char	*qop="auth";
	char	*method="INVITE";
	char	HA1[36];
	char	HA2[36];
	char	response[36];
	char	bin[16];

	digest_HA1(HA1,username,realm,passwd);
	digest_HA2(HA2,method,uri);
	digest_response(response,nonce,nc,cnonce,qop,HA1,HA2);
	printf("response:%s\n",response);
}


#endif
