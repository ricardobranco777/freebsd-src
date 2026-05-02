/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Ricardo (and the FreeBSD Project)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Tests for the Linux-style abstract AF_UNIX namespace.
 *
 * An abstract address has sun_path[0] == '\0'; the rest of sun_path
 * (out to sun_len) is treated as opaque bytes.  The namespace is
 * scoped per-prison by cr_prison identity.
 *
 * These tests cover only the abstract path.  Pathname AF_UNIX is
 * exercised by unix_dgram, unix_stream, and unix_seqpacket_test.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Helpers.
 */

/*
 * Build an abstract sockaddr_un from name bytes.  name may contain
 * embedded NULs; the leading marker NUL is added by this helper.
 * sun_len is set to the exact byte count actually used in sun_path,
 * which is what the kernel uses to delimit the abstract name.
 */
static socklen_t
mkabstract(struct sockaddr_un *sun, const void *name, size_t namelen)
{
	ATF_REQUIRE(namelen + 1 <= sizeof(sun->sun_path));
	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_UNIX;
	sun->sun_path[0] = '\0';
	if (namelen > 0)
		memcpy(&sun->sun_path[1], name, namelen);
	sun->sun_len = offsetof(struct sockaddr_un, sun_path) + 1 + namelen;
	return (sun->sun_len);
}

/*
 * Bind / address-format tests.
 */

ATF_TC_WITHOUT_HEAD(bind_and_close);
ATF_TC_BODY(bind_and_close, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int s;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	slen = mkabstract(&sun, "test_bind_and_close", 19);
	ATF_REQUIRE_EQ(0, bind(s, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(0, close(s));
}

ATF_TC_WITHOUT_HEAD(bind_then_unlink_does_nothing);
ATF_TC_BODY(bind_then_unlink_does_nothing, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int s;

	/*
	 * Abstract bindings are not in the filesystem; unlink(2) on a
	 * pathname collision should not affect them.  We just confirm
	 * binding succeeds even when the corresponding character bytes
	 * happen to look like a path.
	 */
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	slen = mkabstract(&sun, "/tmp/looks_like_a_path", 22);
	ATF_REQUIRE_EQ(0, bind(s, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(-1, access("/tmp/looks_like_a_path", F_OK));
	ATF_REQUIRE_EQ(ENOENT, errno);
	close(s);
}

ATF_TC_WITHOUT_HEAD(bind_duplicate_returns_eaddrinuse);
ATF_TC_BODY(bind_duplicate_returns_eaddrinuse, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int s1, s2;

	s1 = socket(AF_UNIX, SOCK_STREAM, 0);
	s2 = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s1 >= 0 && s2 >= 0);
	slen = mkabstract(&sun, "dup_name", 8);
	ATF_REQUIRE_EQ(0, bind(s1, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(-1, bind(s2, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(EADDRINUSE, errno);
	close(s1);
	close(s2);
}

ATF_TC_WITHOUT_HEAD(bind_after_close_succeeds);
ATF_TC_BODY(bind_after_close_succeeds, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int s1, s2;

	s1 = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s1 >= 0);
	slen = mkabstract(&sun, "rebind_name", 11);
	ATF_REQUIRE_EQ(0, bind(s1, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(0, close(s1));

	/*
	 * Auto-cleanup property: the binding should vanish when the last
	 * reference closes, leaving the name immediately re-bindable.
	 */
	s2 = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s2 >= 0);
	ATF_REQUIRE_EQ(0, bind(s2, (struct sockaddr *)&sun, slen));
	close(s2);
}

ATF_TC_WITHOUT_HEAD(bind_empty_abstract_name);
ATF_TC_BODY(bind_empty_abstract_name, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int s;

	/*
	 * Explicit empty abstract name: sun_path is exactly one byte, the
	 * leading NUL.  Distinct from Linux autobind (zero-length sockaddr
	 * triggering kernel name selection); we accept the explicit case
	 * but do not implement autobind.
	 */
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	slen = mkabstract(&sun, NULL, 0);
	ATF_REQUIRE_EQ(0, bind(s, (struct sockaddr *)&sun, slen));
	close(s);
}

ATF_TC_WITHOUT_HEAD(bind_embedded_nuls_in_name);
ATF_TC_BODY(bind_embedded_nuls_in_name, tc)
{
	struct sockaddr_un sun1, sun2;
	socklen_t slen1, slen2;
	int s1, s2;

	/*
	 * Names with embedded NULs are distinct byte sequences: "a\0b" and
	 * "a\0c" must not collide.  This exercises the "do not use string
	 * functions on abstract names" invariant.
	 */
	s1 = socket(AF_UNIX, SOCK_STREAM, 0);
	s2 = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s1 >= 0 && s2 >= 0);
	slen1 = mkabstract(&sun1, "a\0b", 3);
	slen2 = mkabstract(&sun2, "a\0c", 3);
	ATF_REQUIRE_EQ(0, bind(s1, (struct sockaddr *)&sun1, slen1));
	ATF_REQUIRE_EQ(0, bind(s2, (struct sockaddr *)&sun2, slen2));
	close(s1);
	close(s2);
}

ATF_TC_WITHOUT_HEAD(bind_filesystem_name_does_not_collide);
ATF_TC_BODY(bind_filesystem_name_does_not_collide, tc)
{
	struct sockaddr_un fs_sun, abs_sun;
	socklen_t abs_slen;
	int sf, sa;

	/*
	 * Pathname and abstract namespaces are disjoint: binding "foo" in
	 * the filesystem must not prevent binding "\0foo" in abstract.
	 */
	memset(&fs_sun, 0, sizeof(fs_sun));
	fs_sun.sun_family = AF_UNIX;
	snprintf(fs_sun.sun_path, sizeof(fs_sun.sun_path),
	    "test_fs_collide_%u.sock", (unsigned)getpid());
	fs_sun.sun_len = SUN_LEN(&fs_sun);
	(void)unlink(fs_sun.sun_path);

	sf = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(sf >= 0);
	ATF_REQUIRE_EQ(0, bind(sf, (struct sockaddr *)&fs_sun, fs_sun.sun_len));

	sa = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(sa >= 0);
	abs_slen = mkabstract(&abs_sun, fs_sun.sun_path,
	    strlen(fs_sun.sun_path));
	ATF_REQUIRE_EQ(0, bind(sa, (struct sockaddr *)&abs_sun, abs_slen));

	close(sa);
	close(sf);
	unlink(fs_sun.sun_path);
}

ATF_TC_WITHOUT_HEAD(getsockname_roundtrip);
ATF_TC_BODY(getsockname_roundtrip, tc)
{
	struct sockaddr_un bound, got;
	socklen_t blen, glen;
	int s;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	blen = mkabstract(&bound, "rtrip", 5);
	ATF_REQUIRE_EQ(0, bind(s, (struct sockaddr *)&bound, blen));

	glen = sizeof(got);
	memset(&got, 0xa5, sizeof(got));
	ATF_REQUIRE_EQ(0, getsockname(s, (struct sockaddr *)&got, &glen));
	ATF_REQUIRE_EQ(blen, glen);
	ATF_REQUIRE_EQ(AF_UNIX, got.sun_family);
	ATF_REQUIRE_EQ(0, got.sun_path[0]);
	ATF_REQUIRE_EQ(0, memcmp(got.sun_path, bound.sun_path,
	    blen - offsetof(struct sockaddr_un, sun_path)));
	close(s);
}

/*
 * Connect / listen / accept tests.
 */

ATF_TC_WITHOUT_HEAD(stream_connect_econnrefused_on_missing);
ATF_TC_BODY(stream_connect_econnrefused_on_missing, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int s;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	slen = mkabstract(&sun, "definitely_not_bound", 20);
	ATF_REQUIRE_EQ(-1, connect(s, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(ECONNREFUSED, errno);
	close(s);
}

ATF_TC_WITHOUT_HEAD(stream_connect_accept);
ATF_TC_BODY(stream_connect_accept, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int ls, cs, as;
	char buf[5];

	ls = socket(AF_UNIX, SOCK_STREAM, 0);
	cs = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0 && cs >= 0);
	slen = mkabstract(&sun, "stream_listen", 13);
	ATF_REQUIRE_EQ(0, bind(ls, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(0, listen(ls, 1));
	ATF_REQUIRE_EQ(0, connect(cs, (struct sockaddr *)&sun, slen));
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);
	ATF_REQUIRE_EQ(5, write(cs, "hello", 5));
	ATF_REQUIRE_EQ(5, read(as, buf, 5));
	ATF_REQUIRE_EQ(0, memcmp(buf, "hello", 5));
	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(seqpacket_connect_accept);
ATF_TC_BODY(seqpacket_connect_accept, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int ls, cs, as;
	char buf[16];
	ssize_t n;

	ls = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	cs = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(ls >= 0 && cs >= 0);
	slen = mkabstract(&sun, "seqpacket_listen", 16);
	ATF_REQUIRE_EQ(0, bind(ls, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(0, listen(ls, 1));
	ATF_REQUIRE_EQ(0, connect(cs, (struct sockaddr *)&sun, slen));
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);
	ATF_REQUIRE_EQ(7, write(cs, "datagram", 7));
	n = read(as, buf, sizeof(buf));
	ATF_REQUIRE_EQ(7, n);
	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(dgram_connect_send);
ATF_TC_BODY(dgram_connect_send, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int rs, cs;
	char buf[8];

	rs = socket(AF_UNIX, SOCK_DGRAM, 0);
	cs = socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(rs >= 0 && cs >= 0);
	slen = mkabstract(&sun, "dgram_recv", 10);
	ATF_REQUIRE_EQ(0, bind(rs, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(0, connect(cs, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(4, send(cs, "ping", 4, 0));
	ATF_REQUIRE_EQ(4, recv(rs, buf, sizeof(buf), 0));
	ATF_REQUIRE_EQ(0, memcmp(buf, "ping", 4));
	close(cs);
	close(rs);
}

ATF_TC_WITHOUT_HEAD(dgram_unconnected_sendto);
ATF_TC_BODY(dgram_unconnected_sendto, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int rs, cs;
	char buf[8];

	/*
	 * The sendto-on-unconnected datagram-socket path goes through
	 * unp_connectat() with return_locked=true.  This is the case that
	 * tripped a panic during development; keep it covered explicitly.
	 */
	rs = socket(AF_UNIX, SOCK_DGRAM, 0);
	cs = socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(rs >= 0 && cs >= 0);
	slen = mkabstract(&sun, "dgram_unconn", 12);
	ATF_REQUIRE_EQ(0, bind(rs, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(4, sendto(cs, "ping", 4, 0,
	    (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(4, recv(rs, buf, sizeof(buf), 0));
	ATF_REQUIRE_EQ(0, memcmp(buf, "ping", 4));
	close(cs);
	close(rs);
}

ATF_TC_WITHOUT_HEAD(dgram_unconnected_sendto_loop);
ATF_TC_BODY(dgram_unconnected_sendto_loop, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int rs, cs;
	char buf[8];

	/*
	 * Repeated unconnected sendto stress: the return_locked path is
	 * walked thousands of times.  If reference accounting on that path
	 * is wrong, this should expose it as a leak (eventual ENOBUFS) or
	 * a panic.
	 */
	rs = socket(AF_UNIX, SOCK_DGRAM, 0);
	cs = socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(rs >= 0 && cs >= 0);
	slen = mkabstract(&sun, "dgram_loop", 10);
	ATF_REQUIRE_EQ(0, bind(rs, (struct sockaddr *)&sun, slen));
	for (int i = 0; i < 4096; i++) {
		ATF_REQUIRE_EQ(4, sendto(cs, "ping", 4, 0,
		    (struct sockaddr *)&sun, slen));
		ATF_REQUIRE_EQ(4, recv(rs, buf, sizeof(buf), 0));
	}
	close(cs);
	close(rs);
}

ATF_TC_WITHOUT_HEAD(stream_peer_address);
ATF_TC_BODY(stream_peer_address, tc)
{
	struct sockaddr_un bound, peer;
	socklen_t blen, plen;
	int ls, cs, as;

	ls = socket(AF_UNIX, SOCK_STREAM, 0);
	cs = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0 && cs >= 0);
	blen = mkabstract(&bound, "peer_addr", 9);
	ATF_REQUIRE_EQ(0, bind(ls, (struct sockaddr *)&bound, blen));
	ATF_REQUIRE_EQ(0, listen(ls, 1));
	ATF_REQUIRE_EQ(0, connect(cs, (struct sockaddr *)&bound, blen));
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	plen = sizeof(peer);
	memset(&peer, 0, sizeof(peer));
	ATF_REQUIRE_EQ(0, getpeername(cs, (struct sockaddr *)&peer, &plen));
	ATF_REQUIRE_EQ(blen, plen);
	ATF_REQUIRE_EQ(0, peer.sun_path[0]);
	ATF_REQUIRE_EQ(0, memcmp(peer.sun_path, bound.sun_path,
	    blen - offsetof(struct sockaddr_un, sun_path)));

	close(as);
	close(cs);
	close(ls);
}

/*
 * Auto-cleanup: a listener that exits without closing should free the
 * binding when the kernel reaps the fd.
 */
ATF_TC_WITHOUT_HEAD(child_exit_releases_binding);
ATF_TC_BODY(child_exit_releases_binding, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	pid_t pid;
	int s, status;

	slen = mkabstract(&sun, "child_releases", 14);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0)
			_exit(1);
		if (bind(s, (struct sockaddr *)&sun, slen) != 0)
			_exit(2);
		_exit(0);	/* fd reaped on exit; binding should vanish */
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));

	/* Parent should now be able to bind the same name. */
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	ATF_REQUIRE_EQ(0, bind(s, (struct sockaddr *)&sun, slen));
	close(s);
}

/*
 * Concurrent close-receiver-while-sending stress.  Exercises the
 * lifetime claim under contention: the receiver's socket reference can
 * vanish at any point while the sender is mid-sendto.
 */
struct stress_arg {
	struct sockaddr_un sun;
	socklen_t slen;
	int rs;
};

static void *
stress_close_thread(void *p)
{
	struct stress_arg *a = p;

	usleep(20000);	/* let sender start */
	close(a->rs);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(dgram_concurrent_close_receiver);
ATF_TC_BODY(dgram_concurrent_close_receiver, tc)
{
	struct stress_arg a;
	pthread_t th;
	int cs;

	a.rs = socket(AF_UNIX, SOCK_DGRAM, 0);
	cs = socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(a.rs >= 0 && cs >= 0);
	a.slen = mkabstract(&a.sun, "stress_close", 12);
	ATF_REQUIRE_EQ(0, bind(a.rs, (struct sockaddr *)&a.sun, a.slen));
	ATF_REQUIRE_EQ(0, pthread_create(&th, NULL, stress_close_thread, &a));

	/*
	 * Loop sending until the receiver close completes.  We accept any
	 * combination of success, ECONNREFUSED, ENOBUFS, ENOTCONN; the
	 * point is that the kernel must not panic.
	 */
	for (int i = 0; i < 200000; i++) {
		ssize_t r = sendto(cs, "x", 1, 0,
		    (struct sockaddr *)&a.sun, a.slen);
		if (r < 0 && errno == ECONNREFUSED)
			break;
	}
	pthread_join(th, NULL);
	close(cs);
}

/*
 * Per-prison namespace identity.
 *
 * Bind the same abstract name in two child jails (siblings) and confirm
 * they do not collide and cannot connect to each other.  Also confirm
 * the parent (host) cannot connect to a jail-bound abstract socket.
 */
static int
jail_create(const char *name)
{
	struct iovec iov[6];
	int jid;
	char errmsg[256];

	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = __DECONST(char *, name);
	iov[1].iov_len = strlen(name) + 1;
	iov[2].iov_base = __DECONST(char *, "persist");
	iov[2].iov_len = sizeof("persist");
	iov[3].iov_base = NULL;
	iov[3].iov_len = 0;
	iov[4].iov_base = __DECONST(char *, "errmsg");
	iov[4].iov_len = sizeof("errmsg");
	iov[5].iov_base = errmsg;
	iov[5].iov_len = sizeof(errmsg);

	jid = jail_set(iov, 6, JAIL_CREATE);
	return (jid);
}

ATF_TC(prison_isolation);
ATF_TC_HEAD(prison_isolation, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(prison_isolation, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	pid_t pid_a, pid_b;
	int sync_a[2], sync_b[2];
	int status;
	char dummy;

	slen = mkabstract(&sun, "prison_iso", 10);
	ATF_REQUIRE_EQ(0, pipe(sync_a));
	ATF_REQUIRE_EQ(0, pipe(sync_b));

	/* Child A: enter jail "abs_iso_a", bind, signal parent, wait. */
	pid_a = fork();
	ATF_REQUIRE(pid_a >= 0);
	if (pid_a == 0) {
		int s, jid;

		close(sync_a[0]);
		jid = jail_create("abs_iso_a");
		if (jid < 0)
			_exit(10);
		if (jail_attach(jid) != 0)
			_exit(11);
		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0)
			_exit(12);
		if (bind(s, (struct sockaddr *)&sun, slen) != 0)
			_exit(13);
		if (write(sync_a[1], "x", 1) != 1)
			_exit(14);
		/* keep socket alive until parent finishes the test */
		(void)read(sync_a[1], &dummy, 1);
		_exit(0);
	}
	close(sync_a[1]);
	ATF_REQUIRE_EQ(1, read(sync_a[0], &dummy, 1));

	/* Child B: enter jail "abs_iso_b", same name must succeed. */
	pid_b = fork();
	ATF_REQUIRE(pid_b >= 0);
	if (pid_b == 0) {
		int s, jid;

		close(sync_b[0]);
		jid = jail_create("abs_iso_b");
		if (jid < 0)
			_exit(20);
		if (jail_attach(jid) != 0)
			_exit(21);
		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0)
			_exit(22);
		/* must NOT collide with child A's binding */
		if (bind(s, (struct sockaddr *)&sun, slen) != 0)
			_exit(23);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid_b, waitpid(pid_b, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child B (sibling jail) failed: status=0x%x", status);

	/*
	 * Host: must NOT see the jail-bound socket.  connect should fail
	 * with ECONNREFUSED, not succeed.
	 */
	{
		int s;

		s = socket(AF_UNIX, SOCK_STREAM, 0);
		ATF_REQUIRE(s >= 0);
		ATF_REQUIRE_EQ(-1, connect(s, (struct sockaddr *)&sun, slen));
		ATF_REQUIRE_EQ(ECONNREFUSED, errno);
		close(s);
	}

	/* Release child A. */
	(void)write(sync_a[0], "x", 1);
	ATF_REQUIRE_EQ(pid_a, waitpid(pid_a, &status, 0));
}

/*
 * uipc_chmod must reject mode changes on abstract sockets.
 */
ATF_TC_WITHOUT_HEAD(chmod_rejected);
ATF_TC_BODY(chmod_rejected, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int s;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	slen = mkabstract(&sun, "chmod_test", 10);
	ATF_REQUIRE_EQ(0, bind(s, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(-1, fchmod(s, 0600));
	ATF_REQUIRE_EQ(EINVAL, errno);
	close(s);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bind_and_close);
	ATF_TP_ADD_TC(tp, bind_then_unlink_does_nothing);
	ATF_TP_ADD_TC(tp, bind_duplicate_returns_eaddrinuse);
	ATF_TP_ADD_TC(tp, bind_after_close_succeeds);
	ATF_TP_ADD_TC(tp, bind_empty_abstract_name);
	ATF_TP_ADD_TC(tp, bind_embedded_nuls_in_name);
	ATF_TP_ADD_TC(tp, bind_filesystem_name_does_not_collide);
	ATF_TP_ADD_TC(tp, getsockname_roundtrip);
	ATF_TP_ADD_TC(tp, stream_connect_econnrefused_on_missing);
	ATF_TP_ADD_TC(tp, stream_connect_accept);
	ATF_TP_ADD_TC(tp, seqpacket_connect_accept);
	ATF_TP_ADD_TC(tp, dgram_connect_send);
	ATF_TP_ADD_TC(tp, dgram_unconnected_sendto);
	ATF_TP_ADD_TC(tp, dgram_unconnected_sendto_loop);
	ATF_TP_ADD_TC(tp, stream_peer_address);
	ATF_TP_ADD_TC(tp, child_exit_releases_binding);
	ATF_TP_ADD_TC(tp, dgram_concurrent_close_receiver);
	ATF_TP_ADD_TC(tp, prison_isolation);
	ATF_TP_ADD_TC(tp, chmod_rejected);
	return (atf_no_error());
}
