/***********************************************************************\

	Load Balancer

	Date		Ver		Author		MemoRandom
	Mar 20,2013	1.0		Hiroaki Hata	Created

	(C) 2013 All Copyrights reserved.
*************************************************************************/
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include "http.h"
#include "parser.h"
#include "header.h"
extern void logging(int level,char *msg);


static HTYPE mtype[]=
{
	{"GET",M_GET,0,M_FLAG_GET},
	{"POST",M_POST,0,M_FLAG_POST}, //TR-16
	{"",ELSE_H,0,0}
};

static HTYPE htype[]=
{
//	{"Expires",EXPIRES_H,0},
//	{"Content-Type",CONTENTTYPE_H,0},
//	{"Content-Length",CONTENTLEN_H,0},
//	{"User-Agent",USERAGENT_H,0},
//	{"From",FROM_H,0},
//	{"Max-Forwards",MAXFORWARDS_H,0},
//	{"WWW-Authenticate",WWW_AUTHTC_H,0},
	{"Location",LOCATION_H,0},
	{"Set-Cookie",SETCOOKIE_H,0},
	{"Cookie",COOKIE_H,0},
	{"Host",HOST_H,0},
	{"",ELSE_H,0}
};

static char *get_line(char *buff,char *line);
static int analyze_header(char *buff,PACKET *pkt);
static int first_line(char *buff,PACKET *pkt);


/***************************************************************/
static char *get_line(char *buff,char *line)
//
//
{
#define D	0x0d
#define	A	0x0a

	char	*ptr;
	char	*eol;
	int	n=0;

	*line='\0';
	if(*buff=='\0') return NULL;//EOT
	for(ptr=buff;;ptr++){
		if(n>(CLEN-10)){
			logging(2,"String too long (AnalyzeHeader 349)");
			logging(2,buff);
			return NULL;
		}
		switch(*ptr){
		case D:
			eol=ptr++;
			if(*ptr==A){
				ptr++;
			}
			*eol='\0';
			strcpy(line,buff);
			return ptr;
		case A:
			eol=ptr++;
			*eol='\0';
			strcpy(line,buff);
			return ptr;
		case '\0':
			strcpy(line,buff);
			return NULL;
		default:
			n++;
			break;
		}
	}
	return NULL;
}


static void LowerCase(char *p)
{
	for(;*p;p++){
		if(*p>='A' && *p<='Z') *p=*p+'a'-'A';
	}
}



int analyze_header_type(char *buff,HTYPE *ptr)
{
	int i;
	char	tmp1[CLEN];
	char	tmp2[CLEN];

	if(*buff=='\0'||*buff==0x0a||*buff==0x0d) return Blank;//
	strncpy(tmp1,buff,CLEN);
	LowerCase(tmp1);
	for(i=0;ptr[i].token[0];i++){
		strncpy(tmp2,ptr[i].token,CLEN);
		LowerCase(tmp2);
		if(strcmp(tmp1,tmp2)==0){
			return ptr[i].type;
		}
	}
	return ELSE_H;
}



static int first_line(char *buff,PACKET *pkt)
{
	int 	i,ret=OK;
	char	tmp[3][1024];
	char	*ptr[3];

	for(i=0;i<3;i++){
		ptr[i]=tmp[i];
	}
	if(strncmp(buff,"HTTP",4)==0){
		//Response
		pkt->start.type=HTTP_RESPONSE;
		if(strlen(buff)>SCLEN-1){
			logging(2,"Firstline Size too long(Respose)");
			logging(2,buff);
			return NG;
		}
		strncpy(pkt->start.response,buff,SCLEN-1);//BugFixed 2014/01/05 TR-15
		SeparateLex(buff,' ',ptr,3);
		pkt->start.code=atoi(tmp[1]);
		strcpy(pkt->start.proto,tmp[0]);
		strcpy(pkt->start.method,tmp[2]);
		ret=OK;
	}else{
		pkt->start.type=HTTP_REQUEST;
		SeparateLex(buff,' ',ptr,3);//Method URL Protocol
		if(strlen(tmp[0]) >SCLEN-1) {
			logging(2,"Firstline Size too long");
			logging(2,tmp[0]);
			return NG;
		}
		strncpy(pkt->start.method,tmp[0],SCLEN-1);
		if(strlen(tmp[1]) >SCLEN-1 ){
			logging(2,"Firstline Size too long");
			logging(2,tmp[1]);
			return NG;
		}
		strncpy(pkt->start.url,tmp[1],SCLEN-1);
		if(strlen(tmp[2]) >SCLEN-1) {
			logging(2,"Firstline Size too long");
			logging(2,tmp[2]);
			return NG;
		}
		strncpy(pkt->start.proto,tmp[2],SCLEN-1);
		pkt->start.message=analyze_header_type(tmp[0],mtype);
		if(pkt->start.message==ELSE_H){
			ret=NG;
		}
	}
	return ret;

}


static int analyze_header(char *buff,PACKET *pkt)
{
	int type;
	unsigned int flag;
	char	*p;
	int	ret=0;
	char	header[CLEN];
	COOKIE		*cp,**start,*c;


	//Check Params
	if( buff==NULL||pkt==NULL) {
		logging(3,"Param Error (Analyze Header:110)");
		return NG;
	}
	if(*buff=='\0'||*buff==0x0a||*buff==0x0d) return Blank;
	if(strlen(buff)>CLEN-1){
		logging(3,"Parameter too long(Analyze Header:115)");
		return NG;
	}
	//
	strcpy(header,buff);
	p=strchr(header,':');
	if(p==NULL){
		logging(3,"No header Name (118)");
		return NG;
	}
	*p='\0';
	type=analyze_header_type(header,htype);
	if(type == ELSE_H){
		if(strlen(pkt->header.general)+strlen(buff) >LARGE_BUFF-16){
			return NG;
		}
		strcat(pkt->header.general,buff);
		strcat(pkt->header.general,"\r\n");
		return type;
	}
	flag=0;
	switch(type){
	case LOCATION_H:
		p=strchr(buff,':');p++;
		ret=AnalyzeCharHeader(p,pkt->header.location);
		if(ret!=OK){
			logging(2,"Location Analyze failed");
			logging(2,buff);
			return NG;
		}
		flag=1;
		break;
	case HOST_H:
		p=strchr(buff,':');p++;
		ret=AnalyzeCharHeader(p,pkt->header.host);
		if(ret!=OK){
			logging(2,"Host Analyze failed");
			logging(2,buff);
			return NG;
		}
		flag=1;
		break;
	case COOKIE_H:
	case SETCOOKIE_H:
	case COOKIE2_H:
	case SETCOOKIE2_H:
		p=strchr(buff,':');p++;
		cp=(COOKIE *)malloc(sizeof(COOKIE));
		if(cp ==NULL){
			logging(3,"malloc error(Analyze Header:212)");
			return NG;
		}
		memset(cp,0,sizeof(COOKIE));
		ret=AnalyzeCookieHeader(p,cp);
		if(ret!=OK){
			free(cp);
			logging(2,"Cookie Analyze failed");
			logging(2,buff);
			return NG;
		}
		if(type==COOKIE_H){
			start=&pkt->header.cookie;
		}else if (type==COOKIE2_H){
			start=&pkt->header.cookie2;
		}else if (type==SETCOOKIE_H){
			start=&pkt->header.setcookie;
		}else{
			start=&pkt->header.setcookie2;//BugFixed 2014/01/05 TR-11
		}
		if(*start==NULL){
			*start=cp;
		}else{
			for(c=*start;c->next!=NULL;c=c->next){}//Move to top
			c->next=cp;
		}
		flag=1;
		break;
	/*
	case USERAGENT_H:
		p=strchr(buff,':');p++;
		ret=AnalyzeCharHeader(p,pkt->header.userAgent);
		if(ret!=OK){
			logging(2,"UserAgent Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case CONTENTTYPE_H:
		p=strchr(buff,':');p++;
		ret=AnalyzeCharHeader(p,pkt->header.contentType);
		if(ret!=OK){
			logging(2,"Content-type Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case CONTENTLEN_H:
		p=strchr(buff,':');p++;
		ret=AnalyzeIntHeader(p,&pkt->header.contentLength);
		if(ret!=OK){
			logging(2,"Content-len Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	*/
	default:
		break;
	}
	if(flag==0){
		if(strlen(pkt->header.general)+strlen(buff) >LARGE_BUFF-16){
			return NG;
		}
		strcat(pkt->header.general,buff);
		strcat(pkt->header.general,"\r\n");
	}
	return type;
}


int Exec_AnalyzePDU(char *rbuff,int rlen,PACKET *pkt)
{

	char	line[CLEN];
	char	tmp[CLEN];
	char	*ptr;
	char	*ptr1;
	int		l=1;
//	time_t	tick;
	int	type;
	char	*limit;
	int clen;

	limit=rbuff+rlen;
	ptr=rbuff;
	ptr=get_line(ptr,line);
	/* 2013/07/07 only one line
	if(ptr==NULL) {
		logging(3,"Parameter Error(AnalyzePDU)");
		return NG-1;
	}
	*/
	if(*line){
		if(strlen(pkt->received_header)+strlen(line) < LARGE_BUFF-16){
			strcat(pkt->received_header,line);
			strcat(pkt->received_header,"\r\n");
		}
	}
	type=first_line(line,pkt);
	if(type==NG){
		logging(2,"Packet Format Error(First Line)");
		logging(2,line);
		return NG-10;
	}

	for(;ptr!=NULL;){
		if(*ptr=='\0')
			break; //Add 2013/07/07
		if(ptr>=limit){ //Add 2004/1/13
			type=NG;
			logging(3,"pointer exceeded over limit");
			logging(3,tmp);
			break;  //Add 2004/1/13
		}
		*line='\0';
		//getLine
		for(*tmp='\0';;){
			ptr1=get_line(ptr,tmp);
			l++;
			if(ptr1==NULL){
				type=NG;
				logging(3,"Line ends without CRLF");
				logging(3,tmp);
				goto label1;
			}
			if(*tmp){
				if(strlen(pkt->received_header)+strlen(tmp) < LARGE_BUFF-16){
					strcat(pkt->received_header,tmp);
					strcat(pkt->received_header,"\r\n");
				}
			}
			ptr=ptr1;
			strcat(line,tmp);
			if(*line=='\0' ){
				break;
			}else if(*ptr==' '||*ptr=='\t'){
				continue;
			}
			else break;

		}
		//HeaderType
		type=analyze_header(line,pkt);
		if(type==Blank){
			break;
		}else if(type==NG){
			break;
		}
	}
label1:
	if(type==NG){
		return NG-30;
	}else if(ptr!=NULL){ //Add a condition 2013/07/07
		//retreave contents;
		clen=rlen - (ptr-rbuff);
		if(clen>0){
			ptr1=malloc(clen);
			if(ptr1!=NULL){
				memcpy(ptr1,ptr,clen);
				pkt->contents=ptr1;
				pkt->contents_len=clen;
			}
		}
	}
	l=0;
	return OK;
}

HTYPE *GetMethodList(void)
{
	return mtype;
}
int Exec_ReplaceLocation(PACKET *pkt,char *val)
{
	if(val==NULL||pkt==NULL){
		return -1;
	}
	if(strlen(val)>CLEN-1){
		return -1;
	}
	if(pkt->header.replaced_location[0]!='\0'){
		return -1;//すでに書かれている
	}
	strcpy(pkt->header.replaced_location,val);
	return 0;
}

int Exec_InsertCookie(PACKET *pkt,char *name,char *val,char *path,char *domain)
{
	COOKIE	*cp;
	COOKIE	*c;
	COOKIE_AV *av;
	COOKIE_AV	*a;
	cp=(COOKIE *)malloc(sizeof(COOKIE));
	if(cp ==NULL){
		logging(3,"malloc error(Exec_InsertCookie:212)");
		return NG;
	}
	memset(cp,0,sizeof(COOKIE));
	av=(COOKIE_AV *)malloc(sizeof(COOKIE_AV));
	if(av==NULL){
		free(cp);
		return -1;
	}
	memset(av,0,sizeof(COOKIE_AV));
	strncpy(av->attr, name,CLEN-1);
	strncpy(av->value,val,CLEN-1);
	if(cp->av==NULL){
		cp->av=av;
	}else{
		for(a=cp->av;a->next!=NULL;a=a->next){}//Move to top
		a->next=av;
	}
	if(path!=NULL && *path!='\0'){
		av=(COOKIE_AV *)malloc(sizeof(COOKIE_AV));
		if(av!=NULL){
			strncpy(av->attr, "path",CLEN-1);
			strncpy(av->value,path,CLEN-1);
			for(a=cp->av;a->next!=NULL;a=a->next){}//Move to top
			a->next=av;
		}
	}
	if(domain!=NULL && *domain!='\0'){
		av=(COOKIE_AV *)malloc(sizeof(COOKIE_AV));
		if(av!=NULL){
			strncpy(av->attr, "domain",CLEN-1);
			strncpy(av->value,domain,CLEN-1);
			for(a=cp->av;a->next!=NULL;a=a->next){}//Move to top
			a->next=av;
		}
	}
	//Attach to Packet
	if(pkt->header.setcookie==NULL){
		pkt->header.setcookie=cp;
	}else{
		for(c=pkt->header.setcookie;c->next!=NULL;c=c->next){}//Move to top
		c->next=cp;
	}
	return 0;
}

#ifdef PARSE_MAIN

main()
{
	pktSAGE	pkt;
	static void dump_packet(unsigned char *ptr,int len);
	char	rbuff[128];

	memset(&pkt,0,sizeof(pktSAGE));
	sprintf(rbuff,"SIP/2.0 %d %s\r\nVia:SIP\r\n\r\n",200,"OK");

	dump_packet(rbuff,strlen(rbuff));
//	AnalyzePDU(rbuff,strlen(rbuff),&pkt);

}
#endif



/************************/


