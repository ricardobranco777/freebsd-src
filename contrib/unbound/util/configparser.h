/* A Bison parser, made by GNU Bison 3.7.6.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YY_UTIL_CONFIGPARSER_H_INCLUDED
# define YY_YY_UTIL_CONFIGPARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    SPACE = 258,                   /* SPACE  */
    LETTER = 259,                  /* LETTER  */
    NEWLINE = 260,                 /* NEWLINE  */
    COMMENT = 261,                 /* COMMENT  */
    COLON = 262,                   /* COLON  */
    ANY = 263,                     /* ANY  */
    ZONESTR = 264,                 /* ZONESTR  */
    STRING_ARG = 265,              /* STRING_ARG  */
    VAR_FORCE_TOPLEVEL = 266,      /* VAR_FORCE_TOPLEVEL  */
    VAR_SERVER = 267,              /* VAR_SERVER  */
    VAR_VERBOSITY = 268,           /* VAR_VERBOSITY  */
    VAR_NUM_THREADS = 269,         /* VAR_NUM_THREADS  */
    VAR_PORT = 270,                /* VAR_PORT  */
    VAR_OUTGOING_RANGE = 271,      /* VAR_OUTGOING_RANGE  */
    VAR_INTERFACE = 272,           /* VAR_INTERFACE  */
    VAR_PREFER_IP4 = 273,          /* VAR_PREFER_IP4  */
    VAR_DO_IP4 = 274,              /* VAR_DO_IP4  */
    VAR_DO_IP6 = 275,              /* VAR_DO_IP6  */
    VAR_DO_NAT64 = 276,            /* VAR_DO_NAT64  */
    VAR_PREFER_IP6 = 277,          /* VAR_PREFER_IP6  */
    VAR_DO_UDP = 278,              /* VAR_DO_UDP  */
    VAR_DO_TCP = 279,              /* VAR_DO_TCP  */
    VAR_TCP_MSS = 280,             /* VAR_TCP_MSS  */
    VAR_OUTGOING_TCP_MSS = 281,    /* VAR_OUTGOING_TCP_MSS  */
    VAR_TCP_IDLE_TIMEOUT = 282,    /* VAR_TCP_IDLE_TIMEOUT  */
    VAR_EDNS_TCP_KEEPALIVE = 283,  /* VAR_EDNS_TCP_KEEPALIVE  */
    VAR_EDNS_TCP_KEEPALIVE_TIMEOUT = 284, /* VAR_EDNS_TCP_KEEPALIVE_TIMEOUT  */
    VAR_SOCK_QUEUE_TIMEOUT = 285,  /* VAR_SOCK_QUEUE_TIMEOUT  */
    VAR_CHROOT = 286,              /* VAR_CHROOT  */
    VAR_USERNAME = 287,            /* VAR_USERNAME  */
    VAR_DIRECTORY = 288,           /* VAR_DIRECTORY  */
    VAR_LOGFILE = 289,             /* VAR_LOGFILE  */
    VAR_PIDFILE = 290,             /* VAR_PIDFILE  */
    VAR_MSG_CACHE_SIZE = 291,      /* VAR_MSG_CACHE_SIZE  */
    VAR_MSG_CACHE_SLABS = 292,     /* VAR_MSG_CACHE_SLABS  */
    VAR_NUM_QUERIES_PER_THREAD = 293, /* VAR_NUM_QUERIES_PER_THREAD  */
    VAR_RRSET_CACHE_SIZE = 294,    /* VAR_RRSET_CACHE_SIZE  */
    VAR_RRSET_CACHE_SLABS = 295,   /* VAR_RRSET_CACHE_SLABS  */
    VAR_OUTGOING_NUM_TCP = 296,    /* VAR_OUTGOING_NUM_TCP  */
    VAR_INFRA_HOST_TTL = 297,      /* VAR_INFRA_HOST_TTL  */
    VAR_INFRA_LAME_TTL = 298,      /* VAR_INFRA_LAME_TTL  */
    VAR_INFRA_CACHE_SLABS = 299,   /* VAR_INFRA_CACHE_SLABS  */
    VAR_INFRA_CACHE_NUMHOSTS = 300, /* VAR_INFRA_CACHE_NUMHOSTS  */
    VAR_INFRA_CACHE_LAME_SIZE = 301, /* VAR_INFRA_CACHE_LAME_SIZE  */
    VAR_NAME = 302,                /* VAR_NAME  */
    VAR_STUB_ZONE = 303,           /* VAR_STUB_ZONE  */
    VAR_STUB_HOST = 304,           /* VAR_STUB_HOST  */
    VAR_STUB_ADDR = 305,           /* VAR_STUB_ADDR  */
    VAR_TARGET_FETCH_POLICY = 306, /* VAR_TARGET_FETCH_POLICY  */
    VAR_HARDEN_SHORT_BUFSIZE = 307, /* VAR_HARDEN_SHORT_BUFSIZE  */
    VAR_HARDEN_LARGE_QUERIES = 308, /* VAR_HARDEN_LARGE_QUERIES  */
    VAR_FORWARD_ZONE = 309,        /* VAR_FORWARD_ZONE  */
    VAR_FORWARD_HOST = 310,        /* VAR_FORWARD_HOST  */
    VAR_FORWARD_ADDR = 311,        /* VAR_FORWARD_ADDR  */
    VAR_DO_NOT_QUERY_ADDRESS = 312, /* VAR_DO_NOT_QUERY_ADDRESS  */
    VAR_HIDE_IDENTITY = 313,       /* VAR_HIDE_IDENTITY  */
    VAR_HIDE_VERSION = 314,        /* VAR_HIDE_VERSION  */
    VAR_IDENTITY = 315,            /* VAR_IDENTITY  */
    VAR_VERSION = 316,             /* VAR_VERSION  */
    VAR_HARDEN_GLUE = 317,         /* VAR_HARDEN_GLUE  */
    VAR_MODULE_CONF = 318,         /* VAR_MODULE_CONF  */
    VAR_TRUST_ANCHOR_FILE = 319,   /* VAR_TRUST_ANCHOR_FILE  */
    VAR_TRUST_ANCHOR = 320,        /* VAR_TRUST_ANCHOR  */
    VAR_VAL_OVERRIDE_DATE = 321,   /* VAR_VAL_OVERRIDE_DATE  */
    VAR_BOGUS_TTL = 322,           /* VAR_BOGUS_TTL  */
    VAR_VAL_CLEAN_ADDITIONAL = 323, /* VAR_VAL_CLEAN_ADDITIONAL  */
    VAR_VAL_PERMISSIVE_MODE = 324, /* VAR_VAL_PERMISSIVE_MODE  */
    VAR_INCOMING_NUM_TCP = 325,    /* VAR_INCOMING_NUM_TCP  */
    VAR_MSG_BUFFER_SIZE = 326,     /* VAR_MSG_BUFFER_SIZE  */
    VAR_KEY_CACHE_SIZE = 327,      /* VAR_KEY_CACHE_SIZE  */
    VAR_KEY_CACHE_SLABS = 328,     /* VAR_KEY_CACHE_SLABS  */
    VAR_TRUSTED_KEYS_FILE = 329,   /* VAR_TRUSTED_KEYS_FILE  */
    VAR_VAL_NSEC3_KEYSIZE_ITERATIONS = 330, /* VAR_VAL_NSEC3_KEYSIZE_ITERATIONS  */
    VAR_USE_SYSLOG = 331,          /* VAR_USE_SYSLOG  */
    VAR_OUTGOING_INTERFACE = 332,  /* VAR_OUTGOING_INTERFACE  */
    VAR_ROOT_HINTS = 333,          /* VAR_ROOT_HINTS  */
    VAR_DO_NOT_QUERY_LOCALHOST = 334, /* VAR_DO_NOT_QUERY_LOCALHOST  */
    VAR_CACHE_MAX_TTL = 335,       /* VAR_CACHE_MAX_TTL  */
    VAR_HARDEN_DNSSEC_STRIPPED = 336, /* VAR_HARDEN_DNSSEC_STRIPPED  */
    VAR_ACCESS_CONTROL = 337,      /* VAR_ACCESS_CONTROL  */
    VAR_LOCAL_ZONE = 338,          /* VAR_LOCAL_ZONE  */
    VAR_LOCAL_DATA = 339,          /* VAR_LOCAL_DATA  */
    VAR_INTERFACE_AUTOMATIC = 340, /* VAR_INTERFACE_AUTOMATIC  */
    VAR_STATISTICS_INTERVAL = 341, /* VAR_STATISTICS_INTERVAL  */
    VAR_DO_DAEMONIZE = 342,        /* VAR_DO_DAEMONIZE  */
    VAR_USE_CAPS_FOR_ID = 343,     /* VAR_USE_CAPS_FOR_ID  */
    VAR_STATISTICS_CUMULATIVE = 344, /* VAR_STATISTICS_CUMULATIVE  */
    VAR_OUTGOING_PORT_PERMIT = 345, /* VAR_OUTGOING_PORT_PERMIT  */
    VAR_OUTGOING_PORT_AVOID = 346, /* VAR_OUTGOING_PORT_AVOID  */
    VAR_DLV_ANCHOR_FILE = 347,     /* VAR_DLV_ANCHOR_FILE  */
    VAR_DLV_ANCHOR = 348,          /* VAR_DLV_ANCHOR  */
    VAR_NEG_CACHE_SIZE = 349,      /* VAR_NEG_CACHE_SIZE  */
    VAR_HARDEN_REFERRAL_PATH = 350, /* VAR_HARDEN_REFERRAL_PATH  */
    VAR_PRIVATE_ADDRESS = 351,     /* VAR_PRIVATE_ADDRESS  */
    VAR_PRIVATE_DOMAIN = 352,      /* VAR_PRIVATE_DOMAIN  */
    VAR_REMOTE_CONTROL = 353,      /* VAR_REMOTE_CONTROL  */
    VAR_CONTROL_ENABLE = 354,      /* VAR_CONTROL_ENABLE  */
    VAR_CONTROL_INTERFACE = 355,   /* VAR_CONTROL_INTERFACE  */
    VAR_CONTROL_PORT = 356,        /* VAR_CONTROL_PORT  */
    VAR_SERVER_KEY_FILE = 357,     /* VAR_SERVER_KEY_FILE  */
    VAR_SERVER_CERT_FILE = 358,    /* VAR_SERVER_CERT_FILE  */
    VAR_CONTROL_KEY_FILE = 359,    /* VAR_CONTROL_KEY_FILE  */
    VAR_CONTROL_CERT_FILE = 360,   /* VAR_CONTROL_CERT_FILE  */
    VAR_CONTROL_USE_CERT = 361,    /* VAR_CONTROL_USE_CERT  */
    VAR_TCP_REUSE_TIMEOUT = 362,   /* VAR_TCP_REUSE_TIMEOUT  */
    VAR_MAX_REUSE_TCP_QUERIES = 363, /* VAR_MAX_REUSE_TCP_QUERIES  */
    VAR_EXTENDED_STATISTICS = 364, /* VAR_EXTENDED_STATISTICS  */
    VAR_LOCAL_DATA_PTR = 365,      /* VAR_LOCAL_DATA_PTR  */
    VAR_JOSTLE_TIMEOUT = 366,      /* VAR_JOSTLE_TIMEOUT  */
    VAR_STUB_PRIME = 367,          /* VAR_STUB_PRIME  */
    VAR_UNWANTED_REPLY_THRESHOLD = 368, /* VAR_UNWANTED_REPLY_THRESHOLD  */
    VAR_LOG_TIME_ASCII = 369,      /* VAR_LOG_TIME_ASCII  */
    VAR_DOMAIN_INSECURE = 370,     /* VAR_DOMAIN_INSECURE  */
    VAR_PYTHON = 371,              /* VAR_PYTHON  */
    VAR_PYTHON_SCRIPT = 372,       /* VAR_PYTHON_SCRIPT  */
    VAR_VAL_SIG_SKEW_MIN = 373,    /* VAR_VAL_SIG_SKEW_MIN  */
    VAR_VAL_SIG_SKEW_MAX = 374,    /* VAR_VAL_SIG_SKEW_MAX  */
    VAR_VAL_MAX_RESTART = 375,     /* VAR_VAL_MAX_RESTART  */
    VAR_CACHE_MIN_TTL = 376,       /* VAR_CACHE_MIN_TTL  */
    VAR_VAL_LOG_LEVEL = 377,       /* VAR_VAL_LOG_LEVEL  */
    VAR_AUTO_TRUST_ANCHOR_FILE = 378, /* VAR_AUTO_TRUST_ANCHOR_FILE  */
    VAR_KEEP_MISSING = 379,        /* VAR_KEEP_MISSING  */
    VAR_ADD_HOLDDOWN = 380,        /* VAR_ADD_HOLDDOWN  */
    VAR_DEL_HOLDDOWN = 381,        /* VAR_DEL_HOLDDOWN  */
    VAR_SO_RCVBUF = 382,           /* VAR_SO_RCVBUF  */
    VAR_EDNS_BUFFER_SIZE = 383,    /* VAR_EDNS_BUFFER_SIZE  */
    VAR_PREFETCH = 384,            /* VAR_PREFETCH  */
    VAR_PREFETCH_KEY = 385,        /* VAR_PREFETCH_KEY  */
    VAR_SO_SNDBUF = 386,           /* VAR_SO_SNDBUF  */
    VAR_SO_REUSEPORT = 387,        /* VAR_SO_REUSEPORT  */
    VAR_HARDEN_BELOW_NXDOMAIN = 388, /* VAR_HARDEN_BELOW_NXDOMAIN  */
    VAR_IGNORE_CD_FLAG = 389,      /* VAR_IGNORE_CD_FLAG  */
    VAR_LOG_QUERIES = 390,         /* VAR_LOG_QUERIES  */
    VAR_LOG_REPLIES = 391,         /* VAR_LOG_REPLIES  */
    VAR_LOG_LOCAL_ACTIONS = 392,   /* VAR_LOG_LOCAL_ACTIONS  */
    VAR_TCP_UPSTREAM = 393,        /* VAR_TCP_UPSTREAM  */
    VAR_SSL_UPSTREAM = 394,        /* VAR_SSL_UPSTREAM  */
    VAR_TCP_AUTH_QUERY_TIMEOUT = 395, /* VAR_TCP_AUTH_QUERY_TIMEOUT  */
    VAR_SSL_SERVICE_KEY = 396,     /* VAR_SSL_SERVICE_KEY  */
    VAR_SSL_SERVICE_PEM = 397,     /* VAR_SSL_SERVICE_PEM  */
    VAR_SSL_PORT = 398,            /* VAR_SSL_PORT  */
    VAR_FORWARD_FIRST = 399,       /* VAR_FORWARD_FIRST  */
    VAR_STUB_SSL_UPSTREAM = 400,   /* VAR_STUB_SSL_UPSTREAM  */
    VAR_FORWARD_SSL_UPSTREAM = 401, /* VAR_FORWARD_SSL_UPSTREAM  */
    VAR_TLS_CERT_BUNDLE = 402,     /* VAR_TLS_CERT_BUNDLE  */
    VAR_STUB_TCP_UPSTREAM = 403,   /* VAR_STUB_TCP_UPSTREAM  */
    VAR_FORWARD_TCP_UPSTREAM = 404, /* VAR_FORWARD_TCP_UPSTREAM  */
    VAR_HTTPS_PORT = 405,          /* VAR_HTTPS_PORT  */
    VAR_HTTP_ENDPOINT = 406,       /* VAR_HTTP_ENDPOINT  */
    VAR_HTTP_MAX_STREAMS = 407,    /* VAR_HTTP_MAX_STREAMS  */
    VAR_HTTP_QUERY_BUFFER_SIZE = 408, /* VAR_HTTP_QUERY_BUFFER_SIZE  */
    VAR_HTTP_RESPONSE_BUFFER_SIZE = 409, /* VAR_HTTP_RESPONSE_BUFFER_SIZE  */
    VAR_HTTP_NODELAY = 410,        /* VAR_HTTP_NODELAY  */
    VAR_HTTP_NOTLS_DOWNSTREAM = 411, /* VAR_HTTP_NOTLS_DOWNSTREAM  */
    VAR_STUB_FIRST = 412,          /* VAR_STUB_FIRST  */
    VAR_MINIMAL_RESPONSES = 413,   /* VAR_MINIMAL_RESPONSES  */
    VAR_RRSET_ROUNDROBIN = 414,    /* VAR_RRSET_ROUNDROBIN  */
    VAR_MAX_UDP_SIZE = 415,        /* VAR_MAX_UDP_SIZE  */
    VAR_DELAY_CLOSE = 416,         /* VAR_DELAY_CLOSE  */
    VAR_UDP_CONNECT = 417,         /* VAR_UDP_CONNECT  */
    VAR_UNBLOCK_LAN_ZONES = 418,   /* VAR_UNBLOCK_LAN_ZONES  */
    VAR_INSECURE_LAN_ZONES = 419,  /* VAR_INSECURE_LAN_ZONES  */
    VAR_INFRA_CACHE_MIN_RTT = 420, /* VAR_INFRA_CACHE_MIN_RTT  */
    VAR_INFRA_CACHE_MAX_RTT = 421, /* VAR_INFRA_CACHE_MAX_RTT  */
    VAR_INFRA_KEEP_PROBING = 422,  /* VAR_INFRA_KEEP_PROBING  */
    VAR_DNS64_PREFIX = 423,        /* VAR_DNS64_PREFIX  */
    VAR_DNS64_SYNTHALL = 424,      /* VAR_DNS64_SYNTHALL  */
    VAR_DNS64_IGNORE_AAAA = 425,   /* VAR_DNS64_IGNORE_AAAA  */
    VAR_NAT64_PREFIX = 426,        /* VAR_NAT64_PREFIX  */
    VAR_DNSTAP = 427,              /* VAR_DNSTAP  */
    VAR_DNSTAP_ENABLE = 428,       /* VAR_DNSTAP_ENABLE  */
    VAR_DNSTAP_SOCKET_PATH = 429,  /* VAR_DNSTAP_SOCKET_PATH  */
    VAR_DNSTAP_IP = 430,           /* VAR_DNSTAP_IP  */
    VAR_DNSTAP_TLS = 431,          /* VAR_DNSTAP_TLS  */
    VAR_DNSTAP_TLS_SERVER_NAME = 432, /* VAR_DNSTAP_TLS_SERVER_NAME  */
    VAR_DNSTAP_TLS_CERT_BUNDLE = 433, /* VAR_DNSTAP_TLS_CERT_BUNDLE  */
    VAR_DNSTAP_TLS_CLIENT_KEY_FILE = 434, /* VAR_DNSTAP_TLS_CLIENT_KEY_FILE  */
    VAR_DNSTAP_TLS_CLIENT_CERT_FILE = 435, /* VAR_DNSTAP_TLS_CLIENT_CERT_FILE  */
    VAR_DNSTAP_SEND_IDENTITY = 436, /* VAR_DNSTAP_SEND_IDENTITY  */
    VAR_DNSTAP_SEND_VERSION = 437, /* VAR_DNSTAP_SEND_VERSION  */
    VAR_DNSTAP_BIDIRECTIONAL = 438, /* VAR_DNSTAP_BIDIRECTIONAL  */
    VAR_DNSTAP_IDENTITY = 439,     /* VAR_DNSTAP_IDENTITY  */
    VAR_DNSTAP_VERSION = 440,      /* VAR_DNSTAP_VERSION  */
    VAR_DNSTAP_LOG_RESOLVER_QUERY_MESSAGES = 441, /* VAR_DNSTAP_LOG_RESOLVER_QUERY_MESSAGES  */
    VAR_DNSTAP_LOG_RESOLVER_RESPONSE_MESSAGES = 442, /* VAR_DNSTAP_LOG_RESOLVER_RESPONSE_MESSAGES  */
    VAR_DNSTAP_LOG_CLIENT_QUERY_MESSAGES = 443, /* VAR_DNSTAP_LOG_CLIENT_QUERY_MESSAGES  */
    VAR_DNSTAP_LOG_CLIENT_RESPONSE_MESSAGES = 444, /* VAR_DNSTAP_LOG_CLIENT_RESPONSE_MESSAGES  */
    VAR_DNSTAP_LOG_FORWARDER_QUERY_MESSAGES = 445, /* VAR_DNSTAP_LOG_FORWARDER_QUERY_MESSAGES  */
    VAR_DNSTAP_LOG_FORWARDER_RESPONSE_MESSAGES = 446, /* VAR_DNSTAP_LOG_FORWARDER_RESPONSE_MESSAGES  */
    VAR_DNSTAP_SAMPLE_RATE = 447,  /* VAR_DNSTAP_SAMPLE_RATE  */
    VAR_RESPONSE_IP_TAG = 448,     /* VAR_RESPONSE_IP_TAG  */
    VAR_RESPONSE_IP = 449,         /* VAR_RESPONSE_IP  */
    VAR_RESPONSE_IP_DATA = 450,    /* VAR_RESPONSE_IP_DATA  */
    VAR_HARDEN_ALGO_DOWNGRADE = 451, /* VAR_HARDEN_ALGO_DOWNGRADE  */
    VAR_IP_TRANSPARENT = 452,      /* VAR_IP_TRANSPARENT  */
    VAR_IP_DSCP = 453,             /* VAR_IP_DSCP  */
    VAR_DISABLE_DNSSEC_LAME_CHECK = 454, /* VAR_DISABLE_DNSSEC_LAME_CHECK  */
    VAR_IP_RATELIMIT = 455,        /* VAR_IP_RATELIMIT  */
    VAR_IP_RATELIMIT_SLABS = 456,  /* VAR_IP_RATELIMIT_SLABS  */
    VAR_IP_RATELIMIT_SIZE = 457,   /* VAR_IP_RATELIMIT_SIZE  */
    VAR_RATELIMIT = 458,           /* VAR_RATELIMIT  */
    VAR_RATELIMIT_SLABS = 459,     /* VAR_RATELIMIT_SLABS  */
    VAR_RATELIMIT_SIZE = 460,      /* VAR_RATELIMIT_SIZE  */
    VAR_OUTBOUND_MSG_RETRY = 461,  /* VAR_OUTBOUND_MSG_RETRY  */
    VAR_MAX_SENT_COUNT = 462,      /* VAR_MAX_SENT_COUNT  */
    VAR_MAX_QUERY_RESTARTS = 463,  /* VAR_MAX_QUERY_RESTARTS  */
    VAR_RATELIMIT_FOR_DOMAIN = 464, /* VAR_RATELIMIT_FOR_DOMAIN  */
    VAR_RATELIMIT_BELOW_DOMAIN = 465, /* VAR_RATELIMIT_BELOW_DOMAIN  */
    VAR_IP_RATELIMIT_FACTOR = 466, /* VAR_IP_RATELIMIT_FACTOR  */
    VAR_RATELIMIT_FACTOR = 467,    /* VAR_RATELIMIT_FACTOR  */
    VAR_IP_RATELIMIT_BACKOFF = 468, /* VAR_IP_RATELIMIT_BACKOFF  */
    VAR_RATELIMIT_BACKOFF = 469,   /* VAR_RATELIMIT_BACKOFF  */
    VAR_SEND_CLIENT_SUBNET = 470,  /* VAR_SEND_CLIENT_SUBNET  */
    VAR_CLIENT_SUBNET_ZONE = 471,  /* VAR_CLIENT_SUBNET_ZONE  */
    VAR_CLIENT_SUBNET_ALWAYS_FORWARD = 472, /* VAR_CLIENT_SUBNET_ALWAYS_FORWARD  */
    VAR_CLIENT_SUBNET_OPCODE = 473, /* VAR_CLIENT_SUBNET_OPCODE  */
    VAR_MAX_CLIENT_SUBNET_IPV4 = 474, /* VAR_MAX_CLIENT_SUBNET_IPV4  */
    VAR_MAX_CLIENT_SUBNET_IPV6 = 475, /* VAR_MAX_CLIENT_SUBNET_IPV6  */
    VAR_MIN_CLIENT_SUBNET_IPV4 = 476, /* VAR_MIN_CLIENT_SUBNET_IPV4  */
    VAR_MIN_CLIENT_SUBNET_IPV6 = 477, /* VAR_MIN_CLIENT_SUBNET_IPV6  */
    VAR_MAX_ECS_TREE_SIZE_IPV4 = 478, /* VAR_MAX_ECS_TREE_SIZE_IPV4  */
    VAR_MAX_ECS_TREE_SIZE_IPV6 = 479, /* VAR_MAX_ECS_TREE_SIZE_IPV6  */
    VAR_CAPS_WHITELIST = 480,      /* VAR_CAPS_WHITELIST  */
    VAR_CACHE_MAX_NEGATIVE_TTL = 481, /* VAR_CACHE_MAX_NEGATIVE_TTL  */
    VAR_PERMIT_SMALL_HOLDDOWN = 482, /* VAR_PERMIT_SMALL_HOLDDOWN  */
    VAR_CACHE_MIN_NEGATIVE_TTL = 483, /* VAR_CACHE_MIN_NEGATIVE_TTL  */
    VAR_QNAME_MINIMISATION = 484,  /* VAR_QNAME_MINIMISATION  */
    VAR_QNAME_MINIMISATION_STRICT = 485, /* VAR_QNAME_MINIMISATION_STRICT  */
    VAR_IP_FREEBIND = 486,         /* VAR_IP_FREEBIND  */
    VAR_DEFINE_TAG = 487,          /* VAR_DEFINE_TAG  */
    VAR_LOCAL_ZONE_TAG = 488,      /* VAR_LOCAL_ZONE_TAG  */
    VAR_ACCESS_CONTROL_TAG = 489,  /* VAR_ACCESS_CONTROL_TAG  */
    VAR_LOCAL_ZONE_OVERRIDE = 490, /* VAR_LOCAL_ZONE_OVERRIDE  */
    VAR_ACCESS_CONTROL_TAG_ACTION = 491, /* VAR_ACCESS_CONTROL_TAG_ACTION  */
    VAR_ACCESS_CONTROL_TAG_DATA = 492, /* VAR_ACCESS_CONTROL_TAG_DATA  */
    VAR_VIEW = 493,                /* VAR_VIEW  */
    VAR_ACCESS_CONTROL_VIEW = 494, /* VAR_ACCESS_CONTROL_VIEW  */
    VAR_VIEW_FIRST = 495,          /* VAR_VIEW_FIRST  */
    VAR_SERVE_EXPIRED = 496,       /* VAR_SERVE_EXPIRED  */
    VAR_SERVE_EXPIRED_TTL = 497,   /* VAR_SERVE_EXPIRED_TTL  */
    VAR_SERVE_EXPIRED_TTL_RESET = 498, /* VAR_SERVE_EXPIRED_TTL_RESET  */
    VAR_SERVE_EXPIRED_REPLY_TTL = 499, /* VAR_SERVE_EXPIRED_REPLY_TTL  */
    VAR_SERVE_EXPIRED_CLIENT_TIMEOUT = 500, /* VAR_SERVE_EXPIRED_CLIENT_TIMEOUT  */
    VAR_EDE_SERVE_EXPIRED = 501,   /* VAR_EDE_SERVE_EXPIRED  */
    VAR_SERVE_ORIGINAL_TTL = 502,  /* VAR_SERVE_ORIGINAL_TTL  */
    VAR_FAKE_DSA = 503,            /* VAR_FAKE_DSA  */
    VAR_FAKE_SHA1 = 504,           /* VAR_FAKE_SHA1  */
    VAR_LOG_IDENTITY = 505,        /* VAR_LOG_IDENTITY  */
    VAR_HIDE_TRUSTANCHOR = 506,    /* VAR_HIDE_TRUSTANCHOR  */
    VAR_HIDE_HTTP_USER_AGENT = 507, /* VAR_HIDE_HTTP_USER_AGENT  */
    VAR_HTTP_USER_AGENT = 508,     /* VAR_HTTP_USER_AGENT  */
    VAR_TRUST_ANCHOR_SIGNALING = 509, /* VAR_TRUST_ANCHOR_SIGNALING  */
    VAR_AGGRESSIVE_NSEC = 510,     /* VAR_AGGRESSIVE_NSEC  */
    VAR_USE_SYSTEMD = 511,         /* VAR_USE_SYSTEMD  */
    VAR_SHM_ENABLE = 512,          /* VAR_SHM_ENABLE  */
    VAR_SHM_KEY = 513,             /* VAR_SHM_KEY  */
    VAR_ROOT_KEY_SENTINEL = 514,   /* VAR_ROOT_KEY_SENTINEL  */
    VAR_DNSCRYPT = 515,            /* VAR_DNSCRYPT  */
    VAR_DNSCRYPT_ENABLE = 516,     /* VAR_DNSCRYPT_ENABLE  */
    VAR_DNSCRYPT_PORT = 517,       /* VAR_DNSCRYPT_PORT  */
    VAR_DNSCRYPT_PROVIDER = 518,   /* VAR_DNSCRYPT_PROVIDER  */
    VAR_DNSCRYPT_SECRET_KEY = 519, /* VAR_DNSCRYPT_SECRET_KEY  */
    VAR_DNSCRYPT_PROVIDER_CERT = 520, /* VAR_DNSCRYPT_PROVIDER_CERT  */
    VAR_DNSCRYPT_PROVIDER_CERT_ROTATED = 521, /* VAR_DNSCRYPT_PROVIDER_CERT_ROTATED  */
    VAR_DNSCRYPT_SHARED_SECRET_CACHE_SIZE = 522, /* VAR_DNSCRYPT_SHARED_SECRET_CACHE_SIZE  */
    VAR_DNSCRYPT_SHARED_SECRET_CACHE_SLABS = 523, /* VAR_DNSCRYPT_SHARED_SECRET_CACHE_SLABS  */
    VAR_DNSCRYPT_NONCE_CACHE_SIZE = 524, /* VAR_DNSCRYPT_NONCE_CACHE_SIZE  */
    VAR_DNSCRYPT_NONCE_CACHE_SLABS = 525, /* VAR_DNSCRYPT_NONCE_CACHE_SLABS  */
    VAR_PAD_RESPONSES = 526,       /* VAR_PAD_RESPONSES  */
    VAR_PAD_RESPONSES_BLOCK_SIZE = 527, /* VAR_PAD_RESPONSES_BLOCK_SIZE  */
    VAR_PAD_QUERIES = 528,         /* VAR_PAD_QUERIES  */
    VAR_PAD_QUERIES_BLOCK_SIZE = 529, /* VAR_PAD_QUERIES_BLOCK_SIZE  */
    VAR_IPSECMOD_ENABLED = 530,    /* VAR_IPSECMOD_ENABLED  */
    VAR_IPSECMOD_HOOK = 531,       /* VAR_IPSECMOD_HOOK  */
    VAR_IPSECMOD_IGNORE_BOGUS = 532, /* VAR_IPSECMOD_IGNORE_BOGUS  */
    VAR_IPSECMOD_MAX_TTL = 533,    /* VAR_IPSECMOD_MAX_TTL  */
    VAR_IPSECMOD_WHITELIST = 534,  /* VAR_IPSECMOD_WHITELIST  */
    VAR_IPSECMOD_STRICT = 535,     /* VAR_IPSECMOD_STRICT  */
    VAR_CACHEDB = 536,             /* VAR_CACHEDB  */
    VAR_CACHEDB_BACKEND = 537,     /* VAR_CACHEDB_BACKEND  */
    VAR_CACHEDB_SECRETSEED = 538,  /* VAR_CACHEDB_SECRETSEED  */
    VAR_CACHEDB_REDISHOST = 539,   /* VAR_CACHEDB_REDISHOST  */
    VAR_CACHEDB_REDISREPLICAHOST = 540, /* VAR_CACHEDB_REDISREPLICAHOST  */
    VAR_CACHEDB_REDISPORT = 541,   /* VAR_CACHEDB_REDISPORT  */
    VAR_CACHEDB_REDISREPLICAPORT = 542, /* VAR_CACHEDB_REDISREPLICAPORT  */
    VAR_CACHEDB_REDISTIMEOUT = 543, /* VAR_CACHEDB_REDISTIMEOUT  */
    VAR_CACHEDB_REDISREPLICATIMEOUT = 544, /* VAR_CACHEDB_REDISREPLICATIMEOUT  */
    VAR_CACHEDB_REDISEXPIRERECORDS = 545, /* VAR_CACHEDB_REDISEXPIRERECORDS  */
    VAR_CACHEDB_REDISPATH = 546,   /* VAR_CACHEDB_REDISPATH  */
    VAR_CACHEDB_REDISREPLICAPATH = 547, /* VAR_CACHEDB_REDISREPLICAPATH  */
    VAR_CACHEDB_REDISPASSWORD = 548, /* VAR_CACHEDB_REDISPASSWORD  */
    VAR_CACHEDB_REDISREPLICAPASSWORD = 549, /* VAR_CACHEDB_REDISREPLICAPASSWORD  */
    VAR_CACHEDB_REDISLOGICALDB = 550, /* VAR_CACHEDB_REDISLOGICALDB  */
    VAR_CACHEDB_REDISREPLICALOGICALDB = 551, /* VAR_CACHEDB_REDISREPLICALOGICALDB  */
    VAR_CACHEDB_REDISCOMMANDTIMEOUT = 552, /* VAR_CACHEDB_REDISCOMMANDTIMEOUT  */
    VAR_CACHEDB_REDISREPLICACOMMANDTIMEOUT = 553, /* VAR_CACHEDB_REDISREPLICACOMMANDTIMEOUT  */
    VAR_CACHEDB_REDISCONNECTTIMEOUT = 554, /* VAR_CACHEDB_REDISCONNECTTIMEOUT  */
    VAR_CACHEDB_REDISREPLICACONNECTTIMEOUT = 555, /* VAR_CACHEDB_REDISREPLICACONNECTTIMEOUT  */
    VAR_UDP_UPSTREAM_WITHOUT_DOWNSTREAM = 556, /* VAR_UDP_UPSTREAM_WITHOUT_DOWNSTREAM  */
    VAR_FOR_UPSTREAM = 557,        /* VAR_FOR_UPSTREAM  */
    VAR_AUTH_ZONE = 558,           /* VAR_AUTH_ZONE  */
    VAR_ZONEFILE = 559,            /* VAR_ZONEFILE  */
    VAR_MASTER = 560,              /* VAR_MASTER  */
    VAR_URL = 561,                 /* VAR_URL  */
    VAR_FOR_DOWNSTREAM = 562,      /* VAR_FOR_DOWNSTREAM  */
    VAR_FALLBACK_ENABLED = 563,    /* VAR_FALLBACK_ENABLED  */
    VAR_TLS_ADDITIONAL_PORT = 564, /* VAR_TLS_ADDITIONAL_PORT  */
    VAR_LOW_RTT = 565,             /* VAR_LOW_RTT  */
    VAR_LOW_RTT_PERMIL = 566,      /* VAR_LOW_RTT_PERMIL  */
    VAR_FAST_SERVER_PERMIL = 567,  /* VAR_FAST_SERVER_PERMIL  */
    VAR_FAST_SERVER_NUM = 568,     /* VAR_FAST_SERVER_NUM  */
    VAR_ALLOW_NOTIFY = 569,        /* VAR_ALLOW_NOTIFY  */
    VAR_TLS_WIN_CERT = 570,        /* VAR_TLS_WIN_CERT  */
    VAR_TCP_CONNECTION_LIMIT = 571, /* VAR_TCP_CONNECTION_LIMIT  */
    VAR_ANSWER_COOKIE = 572,       /* VAR_ANSWER_COOKIE  */
    VAR_COOKIE_SECRET = 573,       /* VAR_COOKIE_SECRET  */
    VAR_IP_RATELIMIT_COOKIE = 574, /* VAR_IP_RATELIMIT_COOKIE  */
    VAR_FORWARD_NO_CACHE = 575,    /* VAR_FORWARD_NO_CACHE  */
    VAR_STUB_NO_CACHE = 576,       /* VAR_STUB_NO_CACHE  */
    VAR_LOG_SERVFAIL = 577,        /* VAR_LOG_SERVFAIL  */
    VAR_DENY_ANY = 578,            /* VAR_DENY_ANY  */
    VAR_UNKNOWN_SERVER_TIME_LIMIT = 579, /* VAR_UNKNOWN_SERVER_TIME_LIMIT  */
    VAR_LOG_TAG_QUERYREPLY = 580,  /* VAR_LOG_TAG_QUERYREPLY  */
    VAR_DISCARD_TIMEOUT = 581,     /* VAR_DISCARD_TIMEOUT  */
    VAR_WAIT_LIMIT = 582,          /* VAR_WAIT_LIMIT  */
    VAR_WAIT_LIMIT_COOKIE = 583,   /* VAR_WAIT_LIMIT_COOKIE  */
    VAR_WAIT_LIMIT_NETBLOCK = 584, /* VAR_WAIT_LIMIT_NETBLOCK  */
    VAR_WAIT_LIMIT_COOKIE_NETBLOCK = 585, /* VAR_WAIT_LIMIT_COOKIE_NETBLOCK  */
    VAR_STREAM_WAIT_SIZE = 586,    /* VAR_STREAM_WAIT_SIZE  */
    VAR_TLS_CIPHERS = 587,         /* VAR_TLS_CIPHERS  */
    VAR_TLS_CIPHERSUITES = 588,    /* VAR_TLS_CIPHERSUITES  */
    VAR_TLS_USE_SNI = 589,         /* VAR_TLS_USE_SNI  */
    VAR_IPSET = 590,               /* VAR_IPSET  */
    VAR_IPSET_NAME_V4 = 591,       /* VAR_IPSET_NAME_V4  */
    VAR_IPSET_NAME_V6 = 592,       /* VAR_IPSET_NAME_V6  */
    VAR_TLS_SESSION_TICKET_KEYS = 593, /* VAR_TLS_SESSION_TICKET_KEYS  */
    VAR_RPZ = 594,                 /* VAR_RPZ  */
    VAR_TAGS = 595,                /* VAR_TAGS  */
    VAR_RPZ_ACTION_OVERRIDE = 596, /* VAR_RPZ_ACTION_OVERRIDE  */
    VAR_RPZ_CNAME_OVERRIDE = 597,  /* VAR_RPZ_CNAME_OVERRIDE  */
    VAR_RPZ_LOG = 598,             /* VAR_RPZ_LOG  */
    VAR_RPZ_LOG_NAME = 599,        /* VAR_RPZ_LOG_NAME  */
    VAR_DYNLIB = 600,              /* VAR_DYNLIB  */
    VAR_DYNLIB_FILE = 601,         /* VAR_DYNLIB_FILE  */
    VAR_EDNS_CLIENT_STRING = 602,  /* VAR_EDNS_CLIENT_STRING  */
    VAR_EDNS_CLIENT_STRING_OPCODE = 603, /* VAR_EDNS_CLIENT_STRING_OPCODE  */
    VAR_NSID = 604,                /* VAR_NSID  */
    VAR_ZONEMD_PERMISSIVE_MODE = 605, /* VAR_ZONEMD_PERMISSIVE_MODE  */
    VAR_ZONEMD_CHECK = 606,        /* VAR_ZONEMD_CHECK  */
    VAR_ZONEMD_REJECT_ABSENCE = 607, /* VAR_ZONEMD_REJECT_ABSENCE  */
    VAR_RPZ_SIGNAL_NXDOMAIN_RA = 608, /* VAR_RPZ_SIGNAL_NXDOMAIN_RA  */
    VAR_INTERFACE_AUTOMATIC_PORTS = 609, /* VAR_INTERFACE_AUTOMATIC_PORTS  */
    VAR_EDE = 610,                 /* VAR_EDE  */
    VAR_DNS_ERROR_REPORTING = 611, /* VAR_DNS_ERROR_REPORTING  */
    VAR_INTERFACE_ACTION = 612,    /* VAR_INTERFACE_ACTION  */
    VAR_INTERFACE_VIEW = 613,      /* VAR_INTERFACE_VIEW  */
    VAR_INTERFACE_TAG = 614,       /* VAR_INTERFACE_TAG  */
    VAR_INTERFACE_TAG_ACTION = 615, /* VAR_INTERFACE_TAG_ACTION  */
    VAR_INTERFACE_TAG_DATA = 616,  /* VAR_INTERFACE_TAG_DATA  */
    VAR_QUIC_PORT = 617,           /* VAR_QUIC_PORT  */
    VAR_QUIC_SIZE = 618,           /* VAR_QUIC_SIZE  */
    VAR_PROXY_PROTOCOL_PORT = 619, /* VAR_PROXY_PROTOCOL_PORT  */
    VAR_STATISTICS_INHIBIT_ZERO = 620, /* VAR_STATISTICS_INHIBIT_ZERO  */
    VAR_HARDEN_UNKNOWN_ADDITIONAL = 621, /* VAR_HARDEN_UNKNOWN_ADDITIONAL  */
    VAR_DISABLE_EDNS_DO = 622,     /* VAR_DISABLE_EDNS_DO  */
    VAR_CACHEDB_NO_STORE = 623,    /* VAR_CACHEDB_NO_STORE  */
    VAR_LOG_DESTADDR = 624,        /* VAR_LOG_DESTADDR  */
    VAR_CACHEDB_CHECK_WHEN_SERVE_EXPIRED = 625, /* VAR_CACHEDB_CHECK_WHEN_SERVE_EXPIRED  */
    VAR_COOKIE_SECRET_FILE = 626,  /* VAR_COOKIE_SECRET_FILE  */
    VAR_ITER_SCRUB_NS = 627,       /* VAR_ITER_SCRUB_NS  */
    VAR_ITER_SCRUB_CNAME = 628,    /* VAR_ITER_SCRUB_CNAME  */
    VAR_MAX_GLOBAL_QUOTA = 629,    /* VAR_MAX_GLOBAL_QUOTA  */
    VAR_HARDEN_UNVERIFIED_GLUE = 630, /* VAR_HARDEN_UNVERIFIED_GLUE  */
    VAR_LOG_TIME_ISO = 631         /* VAR_LOG_TIME_ISO  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
#define SPACE 258
#define LETTER 259
#define NEWLINE 260
#define COMMENT 261
#define COLON 262
#define ANY 263
#define ZONESTR 264
#define STRING_ARG 265
#define VAR_FORCE_TOPLEVEL 266
#define VAR_SERVER 267
#define VAR_VERBOSITY 268
#define VAR_NUM_THREADS 269
#define VAR_PORT 270
#define VAR_OUTGOING_RANGE 271
#define VAR_INTERFACE 272
#define VAR_PREFER_IP4 273
#define VAR_DO_IP4 274
#define VAR_DO_IP6 275
#define VAR_DO_NAT64 276
#define VAR_PREFER_IP6 277
#define VAR_DO_UDP 278
#define VAR_DO_TCP 279
#define VAR_TCP_MSS 280
#define VAR_OUTGOING_TCP_MSS 281
#define VAR_TCP_IDLE_TIMEOUT 282
#define VAR_EDNS_TCP_KEEPALIVE 283
#define VAR_EDNS_TCP_KEEPALIVE_TIMEOUT 284
#define VAR_SOCK_QUEUE_TIMEOUT 285
#define VAR_CHROOT 286
#define VAR_USERNAME 287
#define VAR_DIRECTORY 288
#define VAR_LOGFILE 289
#define VAR_PIDFILE 290
#define VAR_MSG_CACHE_SIZE 291
#define VAR_MSG_CACHE_SLABS 292
#define VAR_NUM_QUERIES_PER_THREAD 293
#define VAR_RRSET_CACHE_SIZE 294
#define VAR_RRSET_CACHE_SLABS 295
#define VAR_OUTGOING_NUM_TCP 296
#define VAR_INFRA_HOST_TTL 297
#define VAR_INFRA_LAME_TTL 298
#define VAR_INFRA_CACHE_SLABS 299
#define VAR_INFRA_CACHE_NUMHOSTS 300
#define VAR_INFRA_CACHE_LAME_SIZE 301
#define VAR_NAME 302
#define VAR_STUB_ZONE 303
#define VAR_STUB_HOST 304
#define VAR_STUB_ADDR 305
#define VAR_TARGET_FETCH_POLICY 306
#define VAR_HARDEN_SHORT_BUFSIZE 307
#define VAR_HARDEN_LARGE_QUERIES 308
#define VAR_FORWARD_ZONE 309
#define VAR_FORWARD_HOST 310
#define VAR_FORWARD_ADDR 311
#define VAR_DO_NOT_QUERY_ADDRESS 312
#define VAR_HIDE_IDENTITY 313
#define VAR_HIDE_VERSION 314
#define VAR_IDENTITY 315
#define VAR_VERSION 316
#define VAR_HARDEN_GLUE 317
#define VAR_MODULE_CONF 318
#define VAR_TRUST_ANCHOR_FILE 319
#define VAR_TRUST_ANCHOR 320
#define VAR_VAL_OVERRIDE_DATE 321
#define VAR_BOGUS_TTL 322
#define VAR_VAL_CLEAN_ADDITIONAL 323
#define VAR_VAL_PERMISSIVE_MODE 324
#define VAR_INCOMING_NUM_TCP 325
#define VAR_MSG_BUFFER_SIZE 326
#define VAR_KEY_CACHE_SIZE 327
#define VAR_KEY_CACHE_SLABS 328
#define VAR_TRUSTED_KEYS_FILE 329
#define VAR_VAL_NSEC3_KEYSIZE_ITERATIONS 330
#define VAR_USE_SYSLOG 331
#define VAR_OUTGOING_INTERFACE 332
#define VAR_ROOT_HINTS 333
#define VAR_DO_NOT_QUERY_LOCALHOST 334
#define VAR_CACHE_MAX_TTL 335
#define VAR_HARDEN_DNSSEC_STRIPPED 336
#define VAR_ACCESS_CONTROL 337
#define VAR_LOCAL_ZONE 338
#define VAR_LOCAL_DATA 339
#define VAR_INTERFACE_AUTOMATIC 340
#define VAR_STATISTICS_INTERVAL 341
#define VAR_DO_DAEMONIZE 342
#define VAR_USE_CAPS_FOR_ID 343
#define VAR_STATISTICS_CUMULATIVE 344
#define VAR_OUTGOING_PORT_PERMIT 345
#define VAR_OUTGOING_PORT_AVOID 346
#define VAR_DLV_ANCHOR_FILE 347
#define VAR_DLV_ANCHOR 348
#define VAR_NEG_CACHE_SIZE 349
#define VAR_HARDEN_REFERRAL_PATH 350
#define VAR_PRIVATE_ADDRESS 351
#define VAR_PRIVATE_DOMAIN 352
#define VAR_REMOTE_CONTROL 353
#define VAR_CONTROL_ENABLE 354
#define VAR_CONTROL_INTERFACE 355
#define VAR_CONTROL_PORT 356
#define VAR_SERVER_KEY_FILE 357
#define VAR_SERVER_CERT_FILE 358
#define VAR_CONTROL_KEY_FILE 359
#define VAR_CONTROL_CERT_FILE 360
#define VAR_CONTROL_USE_CERT 361
#define VAR_TCP_REUSE_TIMEOUT 362
#define VAR_MAX_REUSE_TCP_QUERIES 363
#define VAR_EXTENDED_STATISTICS 364
#define VAR_LOCAL_DATA_PTR 365
#define VAR_JOSTLE_TIMEOUT 366
#define VAR_STUB_PRIME 367
#define VAR_UNWANTED_REPLY_THRESHOLD 368
#define VAR_LOG_TIME_ASCII 369
#define VAR_DOMAIN_INSECURE 370
#define VAR_PYTHON 371
#define VAR_PYTHON_SCRIPT 372
#define VAR_VAL_SIG_SKEW_MIN 373
#define VAR_VAL_SIG_SKEW_MAX 374
#define VAR_VAL_MAX_RESTART 375
#define VAR_CACHE_MIN_TTL 376
#define VAR_VAL_LOG_LEVEL 377
#define VAR_AUTO_TRUST_ANCHOR_FILE 378
#define VAR_KEEP_MISSING 379
#define VAR_ADD_HOLDDOWN 380
#define VAR_DEL_HOLDDOWN 381
#define VAR_SO_RCVBUF 382
#define VAR_EDNS_BUFFER_SIZE 383
#define VAR_PREFETCH 384
#define VAR_PREFETCH_KEY 385
#define VAR_SO_SNDBUF 386
#define VAR_SO_REUSEPORT 387
#define VAR_HARDEN_BELOW_NXDOMAIN 388
#define VAR_IGNORE_CD_FLAG 389
#define VAR_LOG_QUERIES 390
#define VAR_LOG_REPLIES 391
#define VAR_LOG_LOCAL_ACTIONS 392
#define VAR_TCP_UPSTREAM 393
#define VAR_SSL_UPSTREAM 394
#define VAR_TCP_AUTH_QUERY_TIMEOUT 395
#define VAR_SSL_SERVICE_KEY 396
#define VAR_SSL_SERVICE_PEM 397
#define VAR_SSL_PORT 398
#define VAR_FORWARD_FIRST 399
#define VAR_STUB_SSL_UPSTREAM 400
#define VAR_FORWARD_SSL_UPSTREAM 401
#define VAR_TLS_CERT_BUNDLE 402
#define VAR_STUB_TCP_UPSTREAM 403
#define VAR_FORWARD_TCP_UPSTREAM 404
#define VAR_HTTPS_PORT 405
#define VAR_HTTP_ENDPOINT 406
#define VAR_HTTP_MAX_STREAMS 407
#define VAR_HTTP_QUERY_BUFFER_SIZE 408
#define VAR_HTTP_RESPONSE_BUFFER_SIZE 409
#define VAR_HTTP_NODELAY 410
#define VAR_HTTP_NOTLS_DOWNSTREAM 411
#define VAR_STUB_FIRST 412
#define VAR_MINIMAL_RESPONSES 413
#define VAR_RRSET_ROUNDROBIN 414
#define VAR_MAX_UDP_SIZE 415
#define VAR_DELAY_CLOSE 416
#define VAR_UDP_CONNECT 417
#define VAR_UNBLOCK_LAN_ZONES 418
#define VAR_INSECURE_LAN_ZONES 419
#define VAR_INFRA_CACHE_MIN_RTT 420
#define VAR_INFRA_CACHE_MAX_RTT 421
#define VAR_INFRA_KEEP_PROBING 422
#define VAR_DNS64_PREFIX 423
#define VAR_DNS64_SYNTHALL 424
#define VAR_DNS64_IGNORE_AAAA 425
#define VAR_NAT64_PREFIX 426
#define VAR_DNSTAP 427
#define VAR_DNSTAP_ENABLE 428
#define VAR_DNSTAP_SOCKET_PATH 429
#define VAR_DNSTAP_IP 430
#define VAR_DNSTAP_TLS 431
#define VAR_DNSTAP_TLS_SERVER_NAME 432
#define VAR_DNSTAP_TLS_CERT_BUNDLE 433
#define VAR_DNSTAP_TLS_CLIENT_KEY_FILE 434
#define VAR_DNSTAP_TLS_CLIENT_CERT_FILE 435
#define VAR_DNSTAP_SEND_IDENTITY 436
#define VAR_DNSTAP_SEND_VERSION 437
#define VAR_DNSTAP_BIDIRECTIONAL 438
#define VAR_DNSTAP_IDENTITY 439
#define VAR_DNSTAP_VERSION 440
#define VAR_DNSTAP_LOG_RESOLVER_QUERY_MESSAGES 441
#define VAR_DNSTAP_LOG_RESOLVER_RESPONSE_MESSAGES 442
#define VAR_DNSTAP_LOG_CLIENT_QUERY_MESSAGES 443
#define VAR_DNSTAP_LOG_CLIENT_RESPONSE_MESSAGES 444
#define VAR_DNSTAP_LOG_FORWARDER_QUERY_MESSAGES 445
#define VAR_DNSTAP_LOG_FORWARDER_RESPONSE_MESSAGES 446
#define VAR_DNSTAP_SAMPLE_RATE 447
#define VAR_RESPONSE_IP_TAG 448
#define VAR_RESPONSE_IP 449
#define VAR_RESPONSE_IP_DATA 450
#define VAR_HARDEN_ALGO_DOWNGRADE 451
#define VAR_IP_TRANSPARENT 452
#define VAR_IP_DSCP 453
#define VAR_DISABLE_DNSSEC_LAME_CHECK 454
#define VAR_IP_RATELIMIT 455
#define VAR_IP_RATELIMIT_SLABS 456
#define VAR_IP_RATELIMIT_SIZE 457
#define VAR_RATELIMIT 458
#define VAR_RATELIMIT_SLABS 459
#define VAR_RATELIMIT_SIZE 460
#define VAR_OUTBOUND_MSG_RETRY 461
#define VAR_MAX_SENT_COUNT 462
#define VAR_MAX_QUERY_RESTARTS 463
#define VAR_RATELIMIT_FOR_DOMAIN 464
#define VAR_RATELIMIT_BELOW_DOMAIN 465
#define VAR_IP_RATELIMIT_FACTOR 466
#define VAR_RATELIMIT_FACTOR 467
#define VAR_IP_RATELIMIT_BACKOFF 468
#define VAR_RATELIMIT_BACKOFF 469
#define VAR_SEND_CLIENT_SUBNET 470
#define VAR_CLIENT_SUBNET_ZONE 471
#define VAR_CLIENT_SUBNET_ALWAYS_FORWARD 472
#define VAR_CLIENT_SUBNET_OPCODE 473
#define VAR_MAX_CLIENT_SUBNET_IPV4 474
#define VAR_MAX_CLIENT_SUBNET_IPV6 475
#define VAR_MIN_CLIENT_SUBNET_IPV4 476
#define VAR_MIN_CLIENT_SUBNET_IPV6 477
#define VAR_MAX_ECS_TREE_SIZE_IPV4 478
#define VAR_MAX_ECS_TREE_SIZE_IPV6 479
#define VAR_CAPS_WHITELIST 480
#define VAR_CACHE_MAX_NEGATIVE_TTL 481
#define VAR_PERMIT_SMALL_HOLDDOWN 482
#define VAR_CACHE_MIN_NEGATIVE_TTL 483
#define VAR_QNAME_MINIMISATION 484
#define VAR_QNAME_MINIMISATION_STRICT 485
#define VAR_IP_FREEBIND 486
#define VAR_DEFINE_TAG 487
#define VAR_LOCAL_ZONE_TAG 488
#define VAR_ACCESS_CONTROL_TAG 489
#define VAR_LOCAL_ZONE_OVERRIDE 490
#define VAR_ACCESS_CONTROL_TAG_ACTION 491
#define VAR_ACCESS_CONTROL_TAG_DATA 492
#define VAR_VIEW 493
#define VAR_ACCESS_CONTROL_VIEW 494
#define VAR_VIEW_FIRST 495
#define VAR_SERVE_EXPIRED 496
#define VAR_SERVE_EXPIRED_TTL 497
#define VAR_SERVE_EXPIRED_TTL_RESET 498
#define VAR_SERVE_EXPIRED_REPLY_TTL 499
#define VAR_SERVE_EXPIRED_CLIENT_TIMEOUT 500
#define VAR_EDE_SERVE_EXPIRED 501
#define VAR_SERVE_ORIGINAL_TTL 502
#define VAR_FAKE_DSA 503
#define VAR_FAKE_SHA1 504
#define VAR_LOG_IDENTITY 505
#define VAR_HIDE_TRUSTANCHOR 506
#define VAR_HIDE_HTTP_USER_AGENT 507
#define VAR_HTTP_USER_AGENT 508
#define VAR_TRUST_ANCHOR_SIGNALING 509
#define VAR_AGGRESSIVE_NSEC 510
#define VAR_USE_SYSTEMD 511
#define VAR_SHM_ENABLE 512
#define VAR_SHM_KEY 513
#define VAR_ROOT_KEY_SENTINEL 514
#define VAR_DNSCRYPT 515
#define VAR_DNSCRYPT_ENABLE 516
#define VAR_DNSCRYPT_PORT 517
#define VAR_DNSCRYPT_PROVIDER 518
#define VAR_DNSCRYPT_SECRET_KEY 519
#define VAR_DNSCRYPT_PROVIDER_CERT 520
#define VAR_DNSCRYPT_PROVIDER_CERT_ROTATED 521
#define VAR_DNSCRYPT_SHARED_SECRET_CACHE_SIZE 522
#define VAR_DNSCRYPT_SHARED_SECRET_CACHE_SLABS 523
#define VAR_DNSCRYPT_NONCE_CACHE_SIZE 524
#define VAR_DNSCRYPT_NONCE_CACHE_SLABS 525
#define VAR_PAD_RESPONSES 526
#define VAR_PAD_RESPONSES_BLOCK_SIZE 527
#define VAR_PAD_QUERIES 528
#define VAR_PAD_QUERIES_BLOCK_SIZE 529
#define VAR_IPSECMOD_ENABLED 530
#define VAR_IPSECMOD_HOOK 531
#define VAR_IPSECMOD_IGNORE_BOGUS 532
#define VAR_IPSECMOD_MAX_TTL 533
#define VAR_IPSECMOD_WHITELIST 534
#define VAR_IPSECMOD_STRICT 535
#define VAR_CACHEDB 536
#define VAR_CACHEDB_BACKEND 537
#define VAR_CACHEDB_SECRETSEED 538
#define VAR_CACHEDB_REDISHOST 539
#define VAR_CACHEDB_REDISREPLICAHOST 540
#define VAR_CACHEDB_REDISPORT 541
#define VAR_CACHEDB_REDISREPLICAPORT 542
#define VAR_CACHEDB_REDISTIMEOUT 543
#define VAR_CACHEDB_REDISREPLICATIMEOUT 544
#define VAR_CACHEDB_REDISEXPIRERECORDS 545
#define VAR_CACHEDB_REDISPATH 546
#define VAR_CACHEDB_REDISREPLICAPATH 547
#define VAR_CACHEDB_REDISPASSWORD 548
#define VAR_CACHEDB_REDISREPLICAPASSWORD 549
#define VAR_CACHEDB_REDISLOGICALDB 550
#define VAR_CACHEDB_REDISREPLICALOGICALDB 551
#define VAR_CACHEDB_REDISCOMMANDTIMEOUT 552
#define VAR_CACHEDB_REDISREPLICACOMMANDTIMEOUT 553
#define VAR_CACHEDB_REDISCONNECTTIMEOUT 554
#define VAR_CACHEDB_REDISREPLICACONNECTTIMEOUT 555
#define VAR_UDP_UPSTREAM_WITHOUT_DOWNSTREAM 556
#define VAR_FOR_UPSTREAM 557
#define VAR_AUTH_ZONE 558
#define VAR_ZONEFILE 559
#define VAR_MASTER 560
#define VAR_URL 561
#define VAR_FOR_DOWNSTREAM 562
#define VAR_FALLBACK_ENABLED 563
#define VAR_TLS_ADDITIONAL_PORT 564
#define VAR_LOW_RTT 565
#define VAR_LOW_RTT_PERMIL 566
#define VAR_FAST_SERVER_PERMIL 567
#define VAR_FAST_SERVER_NUM 568
#define VAR_ALLOW_NOTIFY 569
#define VAR_TLS_WIN_CERT 570
#define VAR_TCP_CONNECTION_LIMIT 571
#define VAR_ANSWER_COOKIE 572
#define VAR_COOKIE_SECRET 573
#define VAR_IP_RATELIMIT_COOKIE 574
#define VAR_FORWARD_NO_CACHE 575
#define VAR_STUB_NO_CACHE 576
#define VAR_LOG_SERVFAIL 577
#define VAR_DENY_ANY 578
#define VAR_UNKNOWN_SERVER_TIME_LIMIT 579
#define VAR_LOG_TAG_QUERYREPLY 580
#define VAR_DISCARD_TIMEOUT 581
#define VAR_WAIT_LIMIT 582
#define VAR_WAIT_LIMIT_COOKIE 583
#define VAR_WAIT_LIMIT_NETBLOCK 584
#define VAR_WAIT_LIMIT_COOKIE_NETBLOCK 585
#define VAR_STREAM_WAIT_SIZE 586
#define VAR_TLS_CIPHERS 587
#define VAR_TLS_CIPHERSUITES 588
#define VAR_TLS_USE_SNI 589
#define VAR_IPSET 590
#define VAR_IPSET_NAME_V4 591
#define VAR_IPSET_NAME_V6 592
#define VAR_TLS_SESSION_TICKET_KEYS 593
#define VAR_RPZ 594
#define VAR_TAGS 595
#define VAR_RPZ_ACTION_OVERRIDE 596
#define VAR_RPZ_CNAME_OVERRIDE 597
#define VAR_RPZ_LOG 598
#define VAR_RPZ_LOG_NAME 599
#define VAR_DYNLIB 600
#define VAR_DYNLIB_FILE 601
#define VAR_EDNS_CLIENT_STRING 602
#define VAR_EDNS_CLIENT_STRING_OPCODE 603
#define VAR_NSID 604
#define VAR_ZONEMD_PERMISSIVE_MODE 605
#define VAR_ZONEMD_CHECK 606
#define VAR_ZONEMD_REJECT_ABSENCE 607
#define VAR_RPZ_SIGNAL_NXDOMAIN_RA 608
#define VAR_INTERFACE_AUTOMATIC_PORTS 609
#define VAR_EDE 610
#define VAR_DNS_ERROR_REPORTING 611
#define VAR_INTERFACE_ACTION 612
#define VAR_INTERFACE_VIEW 613
#define VAR_INTERFACE_TAG 614
#define VAR_INTERFACE_TAG_ACTION 615
#define VAR_INTERFACE_TAG_DATA 616
#define VAR_QUIC_PORT 617
#define VAR_QUIC_SIZE 618
#define VAR_PROXY_PROTOCOL_PORT 619
#define VAR_STATISTICS_INHIBIT_ZERO 620
#define VAR_HARDEN_UNKNOWN_ADDITIONAL 621
#define VAR_DISABLE_EDNS_DO 622
#define VAR_CACHEDB_NO_STORE 623
#define VAR_LOG_DESTADDR 624
#define VAR_CACHEDB_CHECK_WHEN_SERVE_EXPIRED 625
#define VAR_COOKIE_SECRET_FILE 626
#define VAR_ITER_SCRUB_NS 627
#define VAR_ITER_SCRUB_CNAME 628
#define VAR_MAX_GLOBAL_QUOTA 629
#define VAR_HARDEN_UNVERIFIED_GLUE 630
#define VAR_LOG_TIME_ISO 631

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 68 "util/configparser.y"

	char*	str;

#line 823 "util/configparser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_UTIL_CONFIGPARSER_H_INCLUDED  */
