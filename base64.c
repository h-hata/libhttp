#include <stdio.h>
#include <string.h>

void Base64Decode(char *original,size_t len,char *output)
{
	char *ptr=original;
	char b,b2;
	int i;
	int bit=0;
	char *optr=output;
	*optr=0;
	for(i=0;i<len;i++,ptr++){
		printf("%c",*ptr);
		if(*ptr>='A' && *ptr<='Z'){
			b=*ptr-'A';
		}else if(*ptr>='a' && *ptr<='z'){
			b=*ptr-'a'+26;
		}else if(*ptr>='0' && *ptr<='9'){
			b=*ptr-'0'+52;
		}else if(*ptr=='+'){
			b=62;
		}else if(*ptr=='/'){
			b=63;
		}else{
			break;
		}
		if(bit==0){
			b<<=2;
			*optr|=b;
			bit=6;
			continue;
		}else if(bit==6){
			b2=b>>4;
			*optr|=b2;
			printf("(%c)",*optr);
			optr++;
			*optr=0;
			b&=0x0F;
			b<<=4;
			*optr=b;
			bit=4;
			continue;
		}else if(bit==4){
			b2=b>>2;
			*optr|=b2;
			printf("(%c)",*optr);
			optr++;
			*optr=0;
			b&=0x3;
			b<<=6;
			*optr|=b;
			bit=2;
			continue;
		}else if(bit==2){
			*optr|=b;
			printf("(%c)",*optr);
			optr++;
			*optr=0;
			bit=0;
			continue;
		}
	}
}


#ifdef BASE64
main()
{
	char output[128];
	char *orig="QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
	Base64Decode(orig,strlen(orig),output);
	printf("%s\n",output);
}
#endif
