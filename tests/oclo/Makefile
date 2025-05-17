PROGS=		oclo oclo_errors ocloexec_verify

_ALLOW_ABSOLUTE_OBJ_PATH=1

SRCS.oclo=	oclo.c
SRCS.oclo+=	/usr/src/crypto/openssh/openbsd-compat/recallocarray.c
CFLAGS.oclo+=	-I/usr/src/crypto/openssh
SRCS.oclo_errors=	oclo_errors.c
LDADD.ocloexec_verify+=	-lutil
SRCS.ocloexec_verify=	ocloexec_verify.c

MAN=

test:	${PROGS}
	${.CURDIR}/oclo

.include <bsd.progs.mk>
