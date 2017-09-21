/*
 * http.c
 *
 *  Created on: 2013/06/16
 *      Author: hata
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "http.h"
#include "parser.h"

extern int Exec_AnalyzePDU(char *rbuff,int rlen,PACKET *pkt);
extern	PACKET *Exec_AllocPacket(void);
extern void Exec_FreePacket(PACKET *msg);
extern int Exec_InsertCookie(PACKET *pkt,char *name,char *val,char *path,char *domain);
extern int Exec_ReplaceLocation(PACKET *pkt,char *val);
#define MSG_500	"Internal Server Error"
static struct {
	int code;
	char	msg[128];
} st_msg[]={
	{301,"Moved Permanently"},
	{404,"Not Found"},
	{400,"Bad Request"},
	{500,MSG_500},
	{-1,""}
};

static char errmsg[]={
"<!DOCTYPE html>\n\
<html>\n\
<head>\n\
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n\
<title>エラー</title>\n\
</head>\n\
<body>\n\
<h1>エラー</h1>\n\
<p>リクエストを正常に処理できませんでした</p>\n\
</body>\n\
</html>\n"};

int AnalyzePDU(char *rbuff,int rlen,PACKET *pkt)
{
	return Exec_AnalyzePDU(rbuff,rlen,pkt);

}

PACKET *AllocPacket(void)
{
	return Exec_AllocPacket();
}

void FreePacket(PACKET *msg)
{
	Exec_FreePacket(msg);
}

int InsertCookie(PACKET *pkt,char *name,char *val,char *path,char *domain)
{
	return Exec_InsertCookie(pkt,name,val,path,domain);
}

int ReplaceLocation(PACKET *pkt,char *val)
{
	return Exec_ReplaceLocation(pkt,val);
}



int MakeSendBuffer(PACKET *pkt,char *buff,int len)
{
	char	line[CLEN];
	char	tmp[CLEN];
	COOKIE		*cp;
	COOKIE_AV	*ap;
	char *p;
	int		n;
	int slen;
	len-=4;
	*buff='\0';
	if(buff==NULL){
		return -1;
	}
	//一行目
	if(pkt->start.type==HTTP_RESPONSE){
		sprintf(line,"%s %d %s\r\n",pkt->start.proto,pkt->start.code,pkt->start.method);
	}else if(pkt->start.type==HTTP_REQUEST){
		sprintf(line,"%s %s %s\r\n",pkt->start.method,pkt->start.url,pkt->start.proto);
	}else{
		return -20;
	}
	if(len - strlen(buff) < strlen(line)){
		return -30;
	}
	strcat(buff,line);
	//Host出力
	if(pkt->header.host[0]){
		sprintf(line,"Host: %s\r\n",pkt->header.host);
		if(len - strlen(buff) < strlen(line)){
			return -32;
		}
		strcat(buff,line);
	}
	//Location出力
	if(pkt->header.replaced_location[0]){
		sprintf(line,"Location: %s\r\n",pkt->header.replaced_location);
		if(len - strlen(buff) < strlen(line)){
			return -33;
		}
		strcat(buff,line);
	}else if(pkt->header.location[0]){
		sprintf(line,"Location: %s\r\n",pkt->header.location);
		if(len - strlen(buff) < strlen(line)){
			return -34;
		}
		strcat(buff,line);
	}
	//Cookieを出力する
	for(cp=pkt->header.cookie;cp;cp=cp->next){
		strcpy(line,"Cookie: ");
		*tmp='\0';
		for(ap=cp->av;ap;ap=ap->next){
			if(*ap->value){
				sprintf(tmp,"%s=%s; ",ap->attr,ap->value);
			}else{
				sprintf(tmp,"%s; ",ap->attr);
			}
			strcat(line,tmp);
		}
		//末尾の2文字を切り落とす
		n=strlen(line);
		line[n-2]='\0';
		strcat(line,"\r\n");
		if(len - strlen(buff) < strlen(line)){
			return -34;
		}
		strcat(buff,line);
	}
	//Set-Cookieを出力する
	for(cp=pkt->header.setcookie;cp;cp=cp->next){
		strcpy(line,"Set-Cookie: ");
		*tmp='\0';
		for(ap=cp->av;ap;ap=ap->next){
			if(*ap->value){
				sprintf(tmp,"%s=%s; ",ap->attr,ap->value);
			}else{
				sprintf(tmp,"%s; ",ap->attr);
			}
			strcat(line,tmp);
		}
		//末尾の2文字を切り落とす
		n=strlen(line);
		line[n-2]='\0';
		strcat(line,"\r\n");
		if(len - strlen(buff) < strlen(line)){
			return -34;
		}
		strcat(buff,line);
	}


	//一般ヘッダを出力する
	if(len-strlen(buff) < strlen(pkt->header.general)){
		return -40;
	}
	strcat(buff,pkt->header.general);
	//空行
	strcat(buff,"\r\n");
	slen=strlen(buff);
	if(pkt->contents_len>0){
		//ボディ
		if(len-strlen(buff) < pkt->contents_len){
			return -40;
		}
		p=buff+strlen(buff);
		memcpy(p,pkt->contents,pkt->contents_len);
		slen+=pkt->contents_len;
	}
	return slen;
}


int MakeResponseBuffer(PACKET *pkt,int code,char *buff, int len)
{
	char	line[CLEN];
	char *p;
	int slen;
	int i;
	time_t timer;

	len-=4;
	*buff='\0';
	if(buff==NULL){
		return -1;
	}
	p=NULL;
	for(i=0;;i++){
		if(st_msg[i].code==-1){
			break;
		}
		if(st_msg[i].code==code){
			p=st_msg[i].msg;
			break;
		}
	}
	if(p==NULL){
		p="Error";
	}

	//一行目
	sprintf(line,"%s %d %s\r\n",pkt->start.proto,code,p);
	if(len - strlen(buff) < strlen(line)){
		return -30;
	}
	strcat(buff,line);
	//Location出力
	if(pkt->header.replaced_location[0]){
		sprintf(line,"Location: %s\r\n",pkt->header.replaced_location);
		if(len - strlen(buff) < strlen(line)){
			return -33;
		}
		strcat(buff,line);
	}else if(pkt->header.location[0]){
		sprintf(line,"Location: %s\r\n",pkt->header.location);
		if(len - strlen(buff) < strlen(line)){
			return -34;
		}
		strcat(buff,line);
	}
	//Date
	/* 現在時刻の取得 */
	time(&timer);
	/* tm構造体を文字列に変換 */
	p=asctime(localtime(&timer));
	if(p!=NULL){
		if(p[strlen(p)-1]=='\n'){
			p[strlen(p)-1]='\0';
		}
		sprintf(line,"Date: %s\r\n",p);
		if(len - strlen(buff) < strlen(line)){
			return -35;
		}
		strcat(buff,line);
	}
	//Content-length
	i=strlen(errmsg);
	sprintf(line,"Content-Length: %d\r\n",i);
	if(len - strlen(buff) < strlen(line)){
		return -36;
	}
	strcat(buff,line);
	if(i>0){
		strcpy(line,"Content-Type: text/html\r\n\r\n");
		if(len - strlen(buff) < strlen(line)){
			return -37;
		}
		strcat(buff,line);
		if(len - strlen(buff) < i){
			return -38;
		}
		strcat(buff,errmsg);
	}else{
		//空行
		strcat(buff,"\r\n");
	}
	slen=strlen(buff);
	return slen;
}
