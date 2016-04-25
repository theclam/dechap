#define CHAP_NONE '\x00'
#define CHAP_CHALLENGE '\x01'
#define CHAP_RESPONSE '\x02'
#define CHAP_BOTH '\x03'
#define ETHERNET '\x01'
#define VLAN '\x02'
#define MPLS '\x03'
#define PPPoE '\x04'
#define PPP '\x05'
#define CHAP '\x06'
#define IPv4 '\x07'
#define UDP '\x08'
#define RADIUS '\x09'
#define RADAVP '\x0a'
#define L2TP '\x0b'
#define L2AVP '\x0c'
#define OSPFv2 '\x0d'
#define PLAIN_MD5 '\x0e'

typedef struct auth_instance_s {
// A data structure to hold the details necessary to uniquely identify an authentication instance.
	char 	smac[6];
	char 	dmac[6];
	int		svlan;
	int		cvlan;
	int		pppoesid;
	int		authid;
	char	cr;
	int		length;
	char	*challenge_data;
	char	*response_data;
	char	*username;
	char	*ip_ptr;
} auth_instance_t;

typedef struct auth_list_item_s {
// A node for creating linked lists of authentication instances
	struct auth_list_item_s	*next;
	struct auth_list_item_s	*prev;
	auth_instance_t			*item;
} auth_list_item_t;

typedef struct puzzle_s {
// A node for creating linked lists of challenge / response pairs
	struct puzzle_s	*next;
	int				authid;
	int				length;
	char			*challenge;
	char			*response;
	char			*username;
	char			*password;
	char			type;
} puzzle_t;

typedef unsigned int guint32;
typedef unsigned short guint16;
typedef signed int gint32;
typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct params_s {
	char *capfile;
	char *wordfile;
} params_t;

