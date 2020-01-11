# $FreeBSD$

<<<<<<< HEAD
MK_BIND_NOW=	no

CFLAGS+=	${CFLAGS_NO_SIMD} -msoft-float
=======
CFLAGS+=	${CFLAGS_NO_SIMD} -msoft-float -fvisibility=hidden
>>>>>>> origin/freebsd/current/master
