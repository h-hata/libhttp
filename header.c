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
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "http.h"
#include "header.h"
#include "parser.h"
#include "util.h"

static void LowerCase(char *p);
static int search_method(char *p,unsigned int *flag);


static void LowerCase(char *p)
{
	for(;*p;p++){
		if(*p>='A' && *p<='Z') *p=*p+'a'-'A';
	}
}


static int search_method(char *p,unsigned int *flag)
{
	HTYPE	*mlist;
	char	tmp1[32];
	char	tmp2[32];
	unsigned int a=0;
	char	*ptr;
	int		i;
	int		len;

	mlist=GetMethodList();
	if(mlist==NULL) return NG;
	ptr=p;
	for(ptr=p;ptr!=NULL;){
		len=30;
		ptr=SkipChars(ptr,' ');
		ptr=SeparateLex1(ptr,',',tmp1,&len);
		LowerCase(tmp1);
		for(i=0;mlist[i].token[0];i++){
			strncpy(tmp2,mlist[i].token,CLEN);
			LowerCase(tmp2);
			if(strcmp(tmp1,tmp2)==0){
				a|=mlist[i].pos;
				break;
			}
		}
	}
	*flag=a;
	return OK;
}

int AnalyzeIntHeader(char *buff,int  *val)
{
	if(val==NULL||buff==NULL) return -1;
	*val = atoi(buff);
	return OK;
}

int AnalyzeCharHeader(char *buff, char *val)
{
	char	*ptr;
	if(buff==NULL||val==NULL)	return -1;
	ptr=SkipChars(buff,' ');
	if(strlen(ptr) >CLEN-1) return -2;
	strcpy(val,ptr);
	return 0;
}

int AnalyzeMethod(char*p,unsigned int *flag)
{

	return search_method(p,flag);
}


static int extract_av_value(char *ptr,char *v,int size)
{
	int i;
	if(*ptr=='\0'){
		return -1;
	}
	for(i=0;i<size;){
		if(*ptr=='\0'){
			v[i]='\0';
			return 0;
		}
		/*
		if(*ptr=='"'){
			ptr++;
			continue;
		}
		*/
		v[i++]=*ptr++;
	}
	return -1;
}

static int extract_av(char *ptr,char *a,char *v,int size)
{

	int i;
	int f;
	int a_flag;

	ptr=SkipChars(ptr,' ');
	f=0;
	a_flag=0;
	if(*ptr=='\0'){
		return -1;
	}
	//ATTR
	for(i=0;i<size;){
		if(*ptr=='\0'){
			a[i]='\0';
			return 0;
		}
		if(*ptr=='=' && f==0){
			a[i]='\0';
			ptr++;
			a_flag=1;
			break;
		}
		if(*ptr=='"'){
			if(f==0){
				f=1;
			}else{
				f=0;
			}
			ptr++;
			continue;
		}
		a[i++]=*ptr++;
	}
	if(a_flag==0){
		//Attribute���
		return -1;
	}
	//VALUE
	ptr=SkipChars(ptr,' ');
	return extract_av_value(ptr,v,CLEN-1);
}





static int extract_pair(char **start,char *av,int size)
{
	char	*ptr;
	int		i;
	int		f;

	ptr=*start;
	ptr=SkipChars(ptr,' ');
	f=0;
	if(*ptr=='\0'){
		return -1;
	}
	for(i=0;i<size;i++){
		if(*ptr=='\0'){
			av[i]='\0';
			*start=NULL;
			return 0;
		}
		if(*ptr==';' && f==0){
			ptr++;
			*start=ptr;
			av[i]='\0';
			return 0;
		}
		if(*ptr=='"'){
			if(f==0){
				f=1;
			}else{
				f=0;
			}
		}
		av[i]=*ptr++;
	}
	return -1;
}


int AnalyzeCookieHeader(char *buff,COOKIE *cp)
{
	char	*ptr;
	char	av[CLEN];
	char	attr[CLEN];
	char	value[CLEN];
	int	ret;
	COOKIE_AV	*top,*cur;

	top=cp->av;
	for(ptr=buff;ptr!=NULL;){
		ret=extract_pair(&ptr,av,CLEN);
		if(ret!=0){
			return -1;
		}
		ret=extract_av(av,attr,value,CLEN);
		if(ret!=0){
			return -1;
		}
		if(strlen(attr)==0){
			return -1;
		}
		cur=(COOKIE_AV *)malloc(sizeof(COOKIE_AV));
		if(cur==NULL){
			return -1;
		}
		memset(cur,0,sizeof(COOKIE_AV));
		strncpy(cur->attr, attr,CLEN-1);
		strncpy(cur->value,value,CLEN-1);
		if(top==NULL){
			cp->av=cur;
		}else{
			top->next=cur;
		}
		top=cur;
	}
	return 0;
}

