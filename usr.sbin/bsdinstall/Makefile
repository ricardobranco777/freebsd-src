SUBDIR=	distextract distfetch include partedit runconsoles scripts
SUBDIR_PARALLEL=
SUBDIR_DEPEND_distextract = include
SUBDIR_DEPEND_distfetch = include
SUBDIR_DEPEND_partedit = include
SCRIPTS= bsdinstall
MAN= bsdinstall.8
PACKAGE=	bsdinstall

SCRIPTS+=	startbsdinstall
SCRIPTSDIR_startbsdinstall=	${LIBEXECDIR}/bsdinstall

UPDATE_DEPENDFILE= no

FILESDIR=	${SHAREDIR}/bsdinstall
FILES=		FreeBSD-base.conf

_BRANCH!=	${MAKE} -C ${SRCTOP}/release -V BRANCH
BRANCH?=	${_BRANCH}
_REVISION!=	${MAKE} -C ${SRCTOP}/release -V REVISION
REVISION?=	${_REVISION}

.if ${BRANCH} == CURRENT || ${BRANCH} == STABLE
SUBURL=		base_latest
.elif ${BRANCH} == RELEASE
SUBURL=		base_release_${REVISION:C/[0-9]+\.//}
.else
.warning Invalid branch "${BRANCH}"
SUBURL=		base_latest
.endif

FreeBSD-base.conf: FreeBSD-base.conf.in
	sed "s|%%SUBURL%%|${SUBURL}|" < ${.ALLSRC} > ${.TARGET}

.include <bsd.prog.mk>
