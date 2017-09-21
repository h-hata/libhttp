/***********************************************************************\

	Load Balancer

	Date		Ver		Author		MemoRandom
	Mar 20,2013	1.0		Hiroaki Hata	Created

	(C) 2013 All Copyrights reserved.
*************************************************************************/
#ifndef PACKET_H_
#define PACKET_H_

#define FORE	if(fore==1){
#define DEND	}
#define	YES	1
#define NO	0
#define	OK	0
#define	NG	-1
#define	CLEN		1024
#define	SCLEN		256
#define	USER_MAX	32
#define	DOMAIN_MAX	16
#define MAX_BUFF	16384
#define	MAX_HEADER	8000
#define	RECV_TIME_OUT	1
#define	PROCESS_TIME_OUT	10
#define	EXPIRES			3600
#define HASH_LEN	16

#define CRLF	1
#define	BRACE	2
#define	DISPNAME 4
#define	OFF	0
#define	ON	1
#define	REFRESH	2
#define VOID_ST         0
#define WAIT_ST         1
#define PROCEED_ST      2
#define TIMEOUT_ST      3
#define KILLED_ST       4
extern int debug;
extern int fore;

#define	HTTP_REQUEST	1
#define	HTTP_RESPONSE	2

/*-------------------------------METHODS*/
#define	M_ELSE		0
#define	M_GET		1
#define	M_POST		2
#define	M_OPTIONS	3
#define	M_HEAD		4
#define	M_PUT		5
#define	M_DELETE	6
#define	M_TRACE		7
#define	M_CONNECT	8


/*-------------------------------METHODS*/
#define	M_FLAG_ELSE			0
#define	M_FLAG_GET			1
#define	M_FLAG_POST			2

/*--------------------------------Error Code */
#define	E_TRYING	100
#define	E_RINGING	180
#define	E_SUCCESS	200
#define	E_BADREQ	400
#define	E_UNAUTH	401
#define	E_NOTFOUND	404
#define	E_NOTALLOW	405
#define	E_NOTACCEPT	406
#define E_PROXYAUTH	407
#define	E_TIMEOUT	408
#define	E_GONE		410
#define	E_MEDIATYPE	415
#define	E_URI		416
#define	E_TRANSACTION	481
#define	E_MANYHOP	483
#define	E_BUSY		486
#define	E_REQTERM	487
#define	E_SERVER	500
#define	E_IMPLEMENT	501
#define	E_GATEWAY	502
#define	E_VERSION	505

#define	RPORT	1
#define	NET_TCP	2

/*--------------------------------HEADER*/
#define	ACCEPT_H			1
#define	ACCEPTCHARSET_H		2
#define	ACCEPTLANGUAGE_H	3
#define	ACCEPTRABGE_H		4
#define	AGE_H				5
#define	ALLOW_H				6
#define	AUTHORIZATION_H		7
#define	CONNECTION_H		8
#define	CONTENTLANG_H		9
#define	CONTENTTYPE_H		10
#define	CONTENTLEN_H		11
#define	CONTENTLOC_H		12
#define	CONTENTMD5_H		13
#define	CONTENTRANGE_H		14
#define	DATE_H				15
#define	EXPECT_H			16
#define	EXPIRES_H			17
#define	FROM_H				18
#define	HOST_H				19
#define	IFMODSINCE_H		20
#define	IFRANGE_H			21
#define	IFUNMODSINCE_H		22
#define	LASTMOD_H			23
#define	LOCATION_H			24
#define	MAXFORWARDS_H		25
#define	PRAGMA_H			26
#define	RANGE_H				27
#define	REFERER_H			28
#define	RETRYAFTER_H		29
#define	SERVER_H			30
#define	UPGRADE_H			31
#define	USERAGENT_H			32
#define	VARY_H				33
#define WWW_AUTHTC_H		34
#define	COOKIE_H			40
#define	SETCOOKIE_H			41
#define	COOKIE2_H			42
#define	SETCOOKIE2_H		43
#define ELSE_H		9999
#define	Blank		8888

#define PRE_AUTH	0
#define	POST_AUTH	9

/*--------------------------------Cookie Params*/
#define	PEXPIRES	"expires="
#define	PPATH		"path="
#define	PMADDR		"maddr="
#define	PDOMAIN		"domain="
#define	PSECURE		"secure"

//-------------------------------PAuth
#define	PAUTH_REALM	"realm="
#define	PAUTH_USER	"username="
#define	PAUTH_DOMAIN	"domain="
#define PAUTH_QOP	"qop="
#define PAUTH_OPAQUE	"opaque="
#define PAUTH_NONCE	"nonce="
#define PAUTH_CNONCE	"cnonce="
#define	PAUTH_NC	"nc="
#define	PAUTH_URI	"uri="
#define	PAUTH_ALGORITHM	"algorithm="
#define	PAUTH_STALE	"stale="
#define	PAUTH_RESPONSE	"response="

/*--------------------------------TYPEDEF*/
typedef enum{
	CMD_NONE=0,
	CMD_REJECT,
	CMD_REDIRECT,
}CMD;

typedef struct {
	char	token[64];
	int	type;
	int	format;
	unsigned int	pos;
}HTYPE;

typedef struct {
	char	transport[SCLEN];
	char	user[SCLEN];
	char	method[CLEN];
	char	maddr[CLEN];
	char	received[CLEN];
	int	ttl;
	int	lr;
	int		expires;
	double	q;
	char	branch[CLEN];
	char	tag[CLEN];
	char	aux[CLEN];
	int		rport;
}URIPARAM;

typedef struct sipurl_t{
	char	proto[CLEN];
	char	display[CLEN];
	char	username[CLEN];
	char	password[CLEN];
	char	host[CLEN];
	unsigned short int port;
	URIPARAM	param;
	char		tag[CLEN];
	char		aux[CLEN];
	struct sipurl_t	*next;
}URI;

typedef struct {
	int		type;
	int		message;
	char	method[SCLEN];
	char	url[CLEN];
	char	proto[SCLEN];
	int		ver;
	int		code;
	char	response[SCLEN];
}START;

typedef struct pauth_t{
	char	realm[SCLEN];
	char	domain[SCLEN];
	char	qop[SCLEN];
	char	opaque[SCLEN];
	char	nonce[SCLEN];
	char	cnonce[SCLEN];
	char	nc[SCLEN];
	char	uri[SCLEN];
	char	username[SCLEN];
	char	algorithm[SCLEN];
	char	stale[SCLEN];
	char	response[CLEN];
	char	aux[CLEN];
	char	passwd[SCLEN];
	char	method[SCLEN];
	struct pauth_t	*next;
}PAUTH;

//Set-Cookie: param2=GHIJKL; expires=Mon, 31-Dec-2001 23:59:59 GMT; path=/

typedef struct cookie_av{
	char	attr[CLEN];
	char	value[CLEN];
	struct	cookie_av	*next;
}COOKIE_AV;

typedef struct cookie{
	COOKIE_AV	*av;
	struct	cookie	*next;
}COOKIE;

typedef struct {
	char		location[CLEN];
	char		host[CLEN];
	COOKIE		*cookie;
	COOKIE		*cookie2;
	COOKIE		*setcookie;
	COOKIE		*setcookie2;
	char		userAgent[SCLEN];
	char		contentType[SCLEN];
	int			contentLength;
	char		general[8192];
	char		replaced_location[CLEN];
}HEADER;
#define	LARGE_BUFF	8196
typedef	struct {
	START	start;
	HEADER	header;
	char	received_header[LARGE_BUFF];
	char	capture[LARGE_BUFF];
	int		contents_len;
	char	*contents;
	char	*buff;
	int		len;
	char	peer_ip[SCLEN];
	int		peer_port;
	int		server;
	char	server_ip[SCLEN];
	int		server_port;
	char	client_ip[SCLEN];
	int		client_port;
	CMD		cmd;
}PACKET;

typedef struct container_t
{
	char	mes[128];
	URI	to;
	PAUTH	auth;
}CONTAINER;

/*APIs*/
extern int AnalyzePDU(char *rbuff,int rlen,PACKET *pkt);
extern int MakeSendBuffer(PACKET *pkt,char *buff,int len);
extern PACKET *AllocPacket(void);
extern void FreePacket(PACKET *msg);
extern int InsertCookie(PACKET *pkt,char *name,char *val,char *path,char *domain);
extern int ReplaceLocation(PACKET *pkt,char *val);
extern int MakeSendBuffer(PACKET *pkt,char *buff,int len);
extern int MakeResponseBuffer(PACKET *pkt,int status_code,char *buff, int len);
#endif

//------------------------------------------------------------

