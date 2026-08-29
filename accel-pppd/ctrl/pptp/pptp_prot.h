#ifndef PPTP_PROT_H
#define PPTP_PROT_H

#include <sys/types.h>

#define PPTP_MAX_MTU 1436

#define hton8(x)  (x)
#define ntoh8(x)  (x)
#define hton16(x) htons(x)
#define ntoh16(x) ntohs(x)
#define hton32(x) htonl(x)
#define ntoh32(x) ntohl(x)

/* PPTP magic numbers: ----------------------------------------- */

#define PPTP_MAGIC 0x1A2B3C4D /* Magic cookie for PPTP datagrams */
#define PPTP_PORT  1723       /* PPTP TCP port number            */
#define PPTP_PROTO 47         /* PPTP IP protocol number         */

/* PPTP result codes:---------------------------------------- */
#define PPTP_CONN_RES_SUCCESS 1
#define PPTP_CONN_RES_GE      2
#define PPTP_CONN_RES_EXISTS  3
#define PPTP_CONN_RES_AUTH 	  4
#define PPTP_CONN_RES_PROTOCOL 5

#define PPTP_CONN_STOP_OK     1
#define PPTP_CONN_STOP_GE     2

#define PPTP_CALL_RES_OK	    1
#define PPTP_CALL_RES_GE	    2

#define PPTP_GE_NOCONN				1

/* Control Connection Message Types: --------------------------- */

#define PPTP_MESSAGE_CONTROL	1
#define PPTP_MESSAGE_MANAGE		2

/* Control Message Types: -------------------------------------- */

/* (Control Connection Management) */
#define PPTP_START_CTRL_CONN_RQST	1
#define PPTP_START_CTRL_CONN_RPLY	2
#define PPTP_STOP_CTRL_CONN_RQST	3
#define PPTP_STOP_CTRL_CONN_RPLY	4
#define PPTP_ECHO_RQST					5
#define PPTP_ECHO_RPLY					6

/* (Call Management) */
#define PPTP_OUT_CALL_RQST			7
#define PPTP_OUT_CALL_RPLY			8
#define PPTP_IN_CALL_RQST				9
#define PPTP_IN_CALL_RPLY				10
#define PPTP_IN_CALL_CONNECT		11
#define PPTP_CALL_CLEAR_RQST		12
#define PPTP_CALL_CLEAR_NTFY		13

/* (Error Reporting) */
#define PPTP_WAN_ERR_NTFY				14

/* (PPP Session Control) */
#define PPTP_SET_LINK_INFO			15

/* PPTP version information: --------------------------------------*/
#define PPTP_VERSION_STRING			"1.00"
#define PPTP_VERSION						0x100
#define PPTP_FIRMWARE_STRING		"0.01"
#define PPTP_FIRMWARE_VERSION		0x001

#define PPTP_HOSTNAME "local"
#define PPTP_VENDOR   "cananian"

/* PPTP capabilities: ---------------------------------------------*/

/* (Framing capabilities for msg sender) */
#define PPTP_FRAME_ASYNC				1
#define PPTP_FRAME_SYNC					2
#define PPTP_FRAME_ANY          3

/* (Bearer capabilities for msg sender) */
#define PPTP_BEARER_ANALOG			1
#define PPTP_BEARER_DIGITAL 		2
#define PPTP_BEARER_ANY					3

#define PPTP_RESULT_GENERAL_ERROR 2

/* (Reasons to close a connection) */
#define PPTP_STOP_NONE		  		1 /* no good reason                        */
#define PPTP_STOP_PROTOCOL	  	2 /* can't support peer's protocol version */
#define PPTP_STOP_LOCAL_SHUTDOWN  3 /* requester is being shut down          */

/* PPTP datagram structures (all data in network byte order): ----------*/

struct pptp_header
{
  uint16_t length;	  		/* message length in octets, including header */
  uint16_t pptp_type;	  /* PPTP message type. 1 for control message.  */
  uint32_t magic;	  		/* this should be PPTP_MAGIC.                 */
  uint16_t ctrl_type;	  /* Control message type (0-15)                */
  uint16_t reserved0;	  /* reserved.  MUST BE ZERO.                   */
}__attribute__((packed));

struct pptp_start_ctrl_conn /* for control message types 1 and 2 */
{
  struct pptp_header header;

  uint16_t version;      /* PPTP protocol version.  = PPTP_VERSION     */
  uint8_t  result_code;    /* these two fields should be zero on rqst msg*/
  uint8_t  error_code;   /* 0 unless result_code==2 (General Error)    */
  uint32_t framing_cap;  /* Framing capabilities                       */
  uint32_t bearer_cap;   /* Bearer Capabilities                        */
  uint16_t max_channels; /* Maximum Channels (=0 for PNS, PAC ignores) */
  uint16_t firmware_rev; /* Firmware or Software Revision              */
  uint8_t  hostname[64]; /* Host Name (64 octets, zero terminated)     */
  uint8_t  vendor[64];   /* Vendor string (64 octets, zero term.)      */
}__attribute__((packed));

struct pptp_stop_ctrl_conn /* for control message types 3 and 4 */
{
  struct pptp_header header;

  uint8_t reason_result; /* reason for rqst, result for rply          */
  uint8_t error_code;	  /* MUST be 0, unless rply result==2 (general err)*/
  uint16_t reserved1;    /* MUST be 0                                */
}__attribute__((packed));

struct pptp_echo_rqst /* for control message type 5 */
{
  struct pptp_header header;
  uint32_t identifier;   /* arbitrary value set by sender which is used */
                          /* to match up reply and request               */
}__attribute__((packed));

struct pptp_echo_rply /* for control message type 6 */
{
  struct pptp_header header;
  uint32_t identifier;	  /* should correspond to id of rqst             */
  uint8_t result_code;
  uint8_t error_code;    /* =0, unless result_code==2 (general error)   */
  uint16_t reserved1;    /* MUST BE ZERO                                */
}__attribute__((packed));

struct pptp_out_call_rqst /* for control message type 7 */
{
  struct pptp_header header;
  uint16_t call_id;	  /* Call ID (unique id used to multiplex data)  */
  uint16_t call_sernum;  /* Call Serial Number (used for logging)       */
  uint32_t bps_min;      /* Minimum BPS (lowest acceptable line speed)  */
  uint32_t bps_max;	  /* Maximum BPS (highest acceptable line speed) */
  uint32_t bearer;	  /* Bearer type                                 */
  uint32_t framing;      /* Framing type                                */
  uint16_t recv_size;	  /* Recv. Window Size (no. of buffered packets) */
  uint16_t delay;	  /* Packet Processing Delay (in 1/10 sec)       */
  uint16_t phone_len;	  /* Phone Number Length (num. of valid digits)  */
  uint16_t reserved1;    /* MUST BE ZERO				 */
  uint8_t  phone_num[64]; /* Phone Number (64 octets, null term.)       */
  uint8_t subaddress[64]; /* Subaddress (64 octets, null term.)         */
}__attribute__((packed));

struct pptp_out_call_rply /* for control message type 8 */
{
  struct pptp_header header;
  uint16_t call_id;      /* Call ID (used to multiplex data over tunnel)*/
  uint16_t call_id_peer; /* Peer's Call ID (call_id of pptp_out_call_rqst)*/
  uint8_t  result_code;  /* Result Code (1 is no errors)                */
  uint8_t  error_code;   /* Error Code (=0 unless result_code==2)       */
  uint16_t cause_code;   /* Cause Code (addt'l failure information)     */
  uint32_t speed;        /* Connect Speed (in BPS)                      */
  uint16_t recv_size;    /* Recv. Window Size (no. of buffered packets) */
  uint16_t delay;	  /* Packet Processing Delay (in 1/10 sec)       */
  uint32_t channel;      /* Physical Channel ID (for logging)           */
}__attribute__((packed));

struct pptp_in_call_rqst /* for control message type 9 */
{
  struct pptp_header header;
  uint16_t call_id;	  /* Call ID (unique id used to multiplex data)  */
  uint16_t call_sernum;  /* Call Serial Number (used for logging)       */
  uint32_t bearer;	  /* Bearer type                                 */
  uint32_t channel;      /* Physical Channel ID (for logging)           */
  uint16_t dialed_len;   /* Dialed Number Length (# of valid digits)    */
  uint16_t dialing_len;  /* Dialing Number Length (# of valid digits)   */
  uint8_t dialed_num[64]; /* Dialed Number (64 octets, zero term.)      */
  uint8_t dialing_num[64]; /* Dialing Number (64 octets, zero term.)    */
  uint8_t subaddress[64];  /* Subaddress (64 octets, zero term.)        */
}__attribute__((packed));

struct pptp_in_call_rply /* for control message type 10 */
{
  struct pptp_header header;
  uint16_t call_id;      /* Call ID (used to multiplex data over tunnel)*/
  uint16_t call_id_peer; /* Peer's Call ID (call_id of pptp_out_call_rqst)*/
  uint8_t  result_code;  /* Result Code (1 is no errors)                */
  uint8_t  error_code;   /* Error Code (=0 unless result_code==2)       */
  uint16_t recv_size;    /* Recv. Window Size (no. of buffered packets) */
  uint16_t delay;	  /* Packet Processing Delay (in 1/10 sec)       */
  uint16_t reserved1;    /* MUST BE ZERO                                */
}__attribute__((packed));

struct pptp_in_call_connect /* for control message type 11 */
{
  struct pptp_header header;
  uint16_t call_id_peer; /* Peer's Call ID (call_id of pptp_out_call_rqst)*/
  uint16_t reserved1;    /* MUST BE ZERO                                */
  uint32_t speed;        /* Connect Speed (in BPS)                      */
  uint16_t recv_size;    /* Recv. Window Size (no. of buffered packets) */
  uint16_t delay;	  /* Packet Processing Delay (in 1/10 sec)       */
  uint32_t framing;      /* Framing type                                */
}__attribute__((packed));

struct pptp_call_clear_rqst /* for control message type 12 */
{
  struct pptp_header header;
  uint16_t call_id;      /* Call ID (used to multiplex data over tunnel)*/
  uint16_t reserved1;    /* MUST BE ZERO                                */
}__attribute__((packed));

struct pptp_call_clear_ntfy /* for control message type 13 */
{
  struct pptp_header header;
  uint16_t call_id;      /* Call ID (used to multiplex data over tunnel)*/
  uint8_t  result_code;  /* Result Code                                 */
  uint8_t  error_code;   /* Error Code (=0 unless result_code==2)       */
  uint16_t cause_code;   /* Cause Code (for ISDN, is Q.931 cause code)  */
  uint16_t reserved1;    /* MUST BE ZERO                                */
  uint8_t call_stats[128]; /* Call Statistics: 128 octets, ascii, 0-term */
}__attribute__((packed));

struct pptp_wan_err_ntfy  /* for control message type 14 */
{
  struct pptp_header header;
  uint16_t call_id_peer; /* Peer's Call ID (call_id of pptp_out_call_rqst)*/
  uint16_t reserved1;    /* MUST BE ZERO                                */
  uint32_t crc_errors;   /* CRC errors 				 */
  uint32_t frame_errors; /* Framing errors 				 */
  uint32_t hard_errors;  /* Hardware overruns 				 */
  uint32_t buff_errors;  /* Buffer overruns				 */
  uint32_t time_errors;  /* Time-out errors				 */
  uint32_t align_errors; /* Alignment errors				 */
}__attribute__((packed));

struct pptp_set_link_info /* for control message type 15 */
{
  struct pptp_header header;
  uint16_t call_id_peer; /* Peer's Call ID (call_id of pptp_out_call_rqst) */
  uint16_t reserved1;    /* MUST BE ZERO                                   */
  uint32_t send_accm;    /* Send ACCM (for PPP packets; default 0xFFFFFFFF)*/
  uint32_t recv_accm;    /* Receive ACCM (for PPP pack.;default 0xFFFFFFFF)*/
}__attribute__((packed));

/* helpful #defines: -------------------------------------------- */
#define pptp_isvalid_ctrl(header, type, length) \
 (!( ( ntoh16(((struct pptp_header *)header)->length)    < (length)  ) ||   \
     ( ntoh16(((struct pptp_header *)header)->pptp_type) !=(type)    ) ||   \
     ( ntoh32(((struct pptp_header *)header)->magic)     !=PPTP_MAGIC) ||   \
     ( ntoh16(((struct pptp_header *)header)->ctrl_type) > PPTP_SET_LINK_INFO) || \
     ( ntoh16(((struct pptp_header *)header)->reserved0) !=0         ) ))

#define PPTP_HEADER_CTRL(type)  \
{ hton16(PPTP_CTRL_SIZE(type)), \
  hton16(PPTP_MESSAGE_CONTROL), \
  hton32(PPTP_MAGIC),           \
  hton16(type), 0 }

#define PPTP_CTRL_SIZE(type) ( \
(type==PPTP_START_CTRL_CONN_RQST)?sizeof(struct pptp_start_ctrl_conn):	\
(type==PPTP_START_CTRL_CONN_RPLY)?sizeof(struct pptp_start_ctrl_conn):	\
(type==PPTP_STOP_CTRL_CONN_RQST )?sizeof(struct pptp_stop_ctrl_conn):	\
(type==PPTP_STOP_CTRL_CONN_RPLY )?sizeof(struct pptp_stop_ctrl_conn):	\
(type==PPTP_ECHO_RQST           )?sizeof(struct pptp_echo_rqst):	\
(type==PPTP_ECHO_RPLY           )?sizeof(struct pptp_echo_rply):	\
(type==PPTP_OUT_CALL_RQST       )?sizeof(struct pptp_out_call_rqst):	\
(type==PPTP_OUT_CALL_RPLY       )?sizeof(struct pptp_out_call_rply):	\
(type==PPTP_IN_CALL_RQST        )?sizeof(struct pptp_in_call_rqst):	\
(type==PPTP_IN_CALL_RPLY        )?sizeof(struct pptp_in_call_rply):	\
(type==PPTP_IN_CALL_CONNECT     )?sizeof(struct pptp_in_call_connect):	\
(type==PPTP_CALL_CLEAR_RQST     )?sizeof(struct pptp_call_clear_rqst):	\
(type==PPTP_CALL_CLEAR_NTFY     )?sizeof(struct pptp_call_clear_ntfy):	\
(type==PPTP_WAN_ERR_NTFY        )?sizeof(struct pptp_wan_err_ntfy):	\
(type==PPTP_SET_LINK_INFO       )?sizeof(struct pptp_set_link_info):	\
0)
#define PPTP_CTRL_SIZE_MAX (			\
max(sizeof(struct pptp_start_ctrl_conn),	\
max(sizeof(struct pptp_echo_rqst),		\
max(sizeof(struct pptp_echo_rply),		\
max(sizeof(struct pptp_out_call_rqst),		\
max(sizeof(struct pptp_out_call_rply),		\
max(sizeof(struct pptp_in_call_rqst),		\
max(sizeof(struct pptp_in_call_rply),		\
max(sizeof(struct pptp_in_call_connect),	\
max(sizeof(struct pptp_call_clear_rqst),	\
max(sizeof(struct pptp_call_clear_ntfy),	\
max(sizeof(struct pptp_wan_err_ntfy),		\
max(sizeof(struct pptp_set_link_info), 0)))))))))))))

#endif
