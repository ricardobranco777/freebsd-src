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
#include <ctype.h>
#include <errno.h>
#include <jail.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
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
	slen = mkabstract(&sun, "test_bind_and_close", sizeof("test_bind_and_close") - 1);
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
	slen = mkabstract(&sun, "/tmp/looks_like_a_path", sizeof("/tmp/looks_like_a_path") - 1);
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
	slen = mkabstract(&sun, "dup_name", sizeof("dup_name") - 1);
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
	slen = mkabstract(&sun, "rebind_name", sizeof("rebind_name") - 1);
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
	slen1 = mkabstract(&sun1, "a\0b", sizeof("a\0b") - 1);
	slen2 = mkabstract(&sun2, "a\0c", sizeof("a\0c") - 1);
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
	blen = mkabstract(&bound, "rtrip", sizeof("rtrip") - 1);
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
	slen = mkabstract(&sun, "definitely_not_bound", sizeof("definitely_not_bound") - 1);
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
	slen = mkabstract(&sun, "stream_listen", sizeof("stream_listen") - 1);
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
	slen = mkabstract(&sun, "seqpacket_listen", sizeof("seqpacket_listen") - 1);
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
	slen = mkabstract(&sun, "dgram_recv", sizeof("dgram_recv") - 1);
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
	slen = mkabstract(&sun, "dgram_unconn", sizeof("dgram_unconn") - 1);
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
	slen = mkabstract(&sun, "dgram_loop", sizeof("dgram_loop") - 1);
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
	blen = mkabstract(&bound, "peer_addr", sizeof("peer_addr") - 1);
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

	slen = mkabstract(&sun, "child_releases", sizeof("child_releases") - 1);

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
	a.slen = mkabstract(&a.sun, "stress_close", sizeof("stress_close") - 1);
	ATF_REQUIRE_EQ(0, bind(a.rs, (struct sockaddr *)&a.sun, a.slen));
	ATF_REQUIRE_EQ(0, pthread_create(&th, NULL, stress_close_thread, &a));

	/*
	 * Loop sending until the receiver close completes.  Acceptable
	 * outcomes per iteration: success, ECONNREFUSED (break), ENOBUFS,
	 * ENOTCONN.  Anything else is a regression.  We must not abort
	 * inside the loop because the stress thread is still running and
	 * would be left dangling; record the offending errno, break out,
	 * join, then assert.
	 */
	int bad_errno = 0;
	for (int i = 0; i < 200000; i++) {
		ssize_t r = sendto(cs, "x", 1, 0,
		    (struct sockaddr *)&a.sun, a.slen);
		if (r < 0) {
			if (errno == ECONNREFUSED)
				break;
			if (errno != ENOBUFS && errno != ENOTCONN) {
				bad_errno = errno;
				break;
			}
		}
	}
	pthread_join(th, NULL);
	close(cs);
	ATF_REQUIRE_MSG(bad_errno == 0,
	    "unexpected sendto errno %d (%s)",
	    bad_errno, strerror(bad_errno));
}

/*
 * Per-prison namespace identity.
 *
 * Bind the same abstract name in two child jails (siblings) and confirm
 * they do not collide and cannot connect to each other.  Also confirm
 * the parent (host) cannot connect to a jail-bound abstract socket.
 */
/*
 * Create a persistent jail with the given name and return its JID, or
 * -1 on error.  On error, the kernel's diagnostic message is left in
 * the caller-provided errmsg buffer.  Persist is used because the test
 * pattern is "parent creates jail, child briefly attaches then exits";
 * without persist, the jail would die as soon as the last attached
 * process exits.  Cleanup discipline is the caller's responsibility:
 * jail_remove(jid) at teardown.
 */
static int
jail_create(const char *name, char *errmsg, size_t errmsglen)
{
	struct iovec iov[8];

	errmsg[0] = '\0';
	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = __DECONST(char *, name);
	iov[1].iov_len = strlen(name) + 1;
	iov[2].iov_base = __DECONST(char *, "path");
	iov[2].iov_len = sizeof("path");
	iov[3].iov_base = __DECONST(char *, "/");
	iov[3].iov_len = sizeof("/");
	iov[4].iov_base = __DECONST(char *, "persist");
	iov[4].iov_len = sizeof("persist");
	iov[5].iov_base = NULL;
	iov[5].iov_len = 0;
	iov[6].iov_base = __DECONST(char *, "errmsg");
	iov[6].iov_len = sizeof("errmsg");
	iov[7].iov_base = errmsg;
	iov[7].iov_len = errmsglen;

	return (jail_set(iov, nitems(iov), JAIL_CREATE));
}

ATF_TC_WITH_CLEANUP(prison_isolation);
ATF_TC_HEAD(prison_isolation, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(prison_isolation, tc)
{
	char jail_a[64], jail_b[64];
	char errmsg[256];
	struct sockaddr_un sun;
	socklen_t slen;
	pid_t pid_a = -1, pid_b = -1;
	int jid_a = -1, jid_b = -1;
	int sp_a[2] = {-1, -1};
	int status;
	char dummy;
	bool child_a_synced = false;	/* parent has reaped child A's "x" */
	int child_b_status = -1;	/* WEXITSTATUS-encoded; -1 = not run */
	bool host_check_ran = false;
	int host_connect_errno = 0;
	bool host_connect_unexpected_success = false;

	slen = mkabstract(&sun, "prison_iso", sizeof("prison_iso") - 1);

	/*
	 * Parent creates both persistent jails up front and owns the JIDs.
	 * Children jail_attach() into those jails; parent jail_remove()s
	 * them at teardown.  PID-qualified names avoid collisions with
	 * concurrent runs and stale jails from interrupted runs.
	 */
	snprintf(jail_a, sizeof(jail_a), "abs_iso_a_%ld", (long)getpid());
	snprintf(jail_b, sizeof(jail_b), "abs_iso_b_%ld", (long)getpid());
	jid_a = jail_create(jail_a, errmsg, sizeof(errmsg));
	ATF_REQUIRE_MSG(jid_a > 0, "jail_create(%s) failed: %s", jail_a,
	    errmsg[0] != '\0' ? errmsg : strerror(errno));
	jid_b = jail_create(jail_b, errmsg, sizeof(errmsg));
	ATF_REQUIRE_MSG(jid_b > 0, "jail_create(%s) failed: %s", jail_b,
	    errmsg[0] != '\0' ? errmsg : strerror(errno));

	/*
	 * Only child A needs synchronization (parent must keep its socket
	 * alive until the test finishes inspecting cross-jail visibility).
	 * A pipe is unidirectional (reading from the write end returns EOF
	 * immediately on FreeBSD); a socketpair is bidirectional and blocks
	 * correctly in both directions.  Using AF_UNIX for the test's own
	 * IPC is appropriate given what the test exercises.
	 */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp_a));

	/* Child A: enter jail A, bind, signal parent, wait for release. */
	pid_a = fork();
	ATF_REQUIRE(pid_a >= 0);
	if (pid_a == 0) {
		int s;

		close(sp_a[0]);
		if (jail_attach(jid_a) != 0)
			_exit(10);
		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0)
			_exit(11);
		if (bind(s, (struct sockaddr *)&sun, slen) != 0)
			_exit(12);
		if (write(sp_a[1], "x", 1) != 1)
			_exit(13);
		if (read(sp_a[1], &dummy, 1) != 1)
			_exit(14);
		_exit(0);
	}
	close(sp_a[1]);
	sp_a[1] = -1;
	ATF_REQUIRE_EQ(1, read(sp_a[0], &dummy, 1));
	child_a_synced = true;

	/*
	 * From here on, child A is blocked in its read(sp_a[1]).  ATF_REQUIRE
	 * failures would skip the release-and-wait sequence and leave child A
	 * hanging until the kernel reaps the process on ATF cleanup, which
	 * looks like a kyua hang.  Use ATF_CHECK / saved state and route
	 * everything through the out: cleanup label.
	 */

	/* Child B: enter jail B, same name must succeed.  No sync needed. */
	pid_b = fork();
	if (pid_b < 0)
		goto out;
	if (pid_b == 0) {
		int s;

		close(sp_a[0]);
		if (jail_attach(jid_b) != 0)
			_exit(20);
		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0)
			_exit(21);
		/* Must NOT collide with child A's binding. */
		if (bind(s, (struct sockaddr *)&sun, slen) != 0)
			_exit(22);
		_exit(0);
	}
	if (waitpid(pid_b, &status, 0) != pid_b)
		goto out;
	pid_b = -1;	/* reaped */
	child_b_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

	/*
	 * Host: must NOT see the jail-bound socket.  connect should fail
	 * with ECONNREFUSED.
	 */
	{
		int s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0)
			goto out;
		host_check_ran = true;
		if (connect(s, (struct sockaddr *)&sun, slen) == 0)
			host_connect_unexpected_success = true;
		else
			host_connect_errno = errno;
		close(s);
	}

out:
	/*
	 * Cleanup, in reverse order of acquisition.  Each step tolerates
	 * the resource not having been acquired (sentinels above).
	 */
	if (child_a_synced && sp_a[0] >= 0) {
		(void)write(sp_a[0], "x", 1);
	}
	if (sp_a[0] >= 0)
		close(sp_a[0]);
	if (sp_a[1] >= 0)
		close(sp_a[1]);
	if (pid_a > 0)
		(void)waitpid(pid_a, &status, 0);
	if (pid_b > 0)
		(void)waitpid(pid_b, NULL, 0);

	if (jid_a > 0) {
		ATF_CHECK_EQ_MSG(0, jail_remove(jid_a),
		    "jail_remove(jid_a=%d) failed: %s",
		    jid_a, strerror(errno));
	}
	if (jid_b > 0) {
		ATF_CHECK_EQ_MSG(0, jail_remove(jid_b),
		    "jail_remove(jid_b=%d) failed: %s",
		    jid_b, strerror(errno));
	}

	/* Now report the test outcome. */
	ATF_REQUIRE_MSG(child_b_status >= 0,
	    "child B never completed; an earlier setup step failed");
	ATF_REQUIRE_MSG(child_b_status == 0,
	    "child B (sibling jail) failed: exit status %d", child_b_status);
	ATF_REQUIRE_MSG(host_check_ran,
	    "host visibility check did not run; an earlier setup step "
	    "failed");
	ATF_REQUIRE_MSG(!host_connect_unexpected_success,
	    "host should NOT see jail-bound abstract socket, but connect "
	    "succeeded");
	ATF_REQUIRE_EQ_MSG(ECONNREFUSED, host_connect_errno,
	    "host connect: expected ECONNREFUSED, got errno %d (%s)",
	    host_connect_errno, strerror(host_connect_errno));
}
ATF_TC_CLEANUP(prison_isolation, tc)
{
	/*
	 * Best-effort fallback if the body bailed before reaching
	 * jail_remove().  Look up by PID-qualified name and remove.
	 * Failures are silent: "not found" is the expected case after a
	 * clean run.
	 */
	char jail_a[64], jail_b[64];
	int jid;

	snprintf(jail_a, sizeof(jail_a), "abs_iso_a_%ld", (long)getpid());
	snprintf(jail_b, sizeof(jail_b), "abs_iso_b_%ld", (long)getpid());
	if ((jid = jail_getid(jail_a)) > 0)
		(void)jail_remove(jid);
	if ((jid = jail_getid(jail_b)) > 0)
		(void)jail_remove(jid);
}

/*
 * The same abstract name may be bound simultaneously by sockets of
 * different so_type within one prison.  Linux behaves this way (the
 * abstract namespace hash key includes sk_type), so Linuxulator
 * compatibility requires we match it.  Same name, same type still
 * collides with EADDRINUSE.
 */
ATF_TC_WITHOUT_HEAD(type_independence);
ATF_TC_BODY(type_independence, tc)
{
	struct sockaddr_un sun;
	socklen_t slen;
	int s_stream, s_dgram, s_seq, s_stream2;

	slen = mkabstract(&sun, "type_indep", sizeof("type_indep") - 1);

	s_stream = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s_stream >= 0);
	ATF_REQUIRE_EQ(0, bind(s_stream, (struct sockaddr *)&sun, slen));

	s_dgram = socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(s_dgram >= 0);
	ATF_CHECK_EQ_MSG(0, bind(s_dgram, (struct sockaddr *)&sun, slen),
	    "SOCK_DGRAM bind to same name as SOCK_STREAM should succeed: %s",
	    strerror(errno));

	s_seq = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(s_seq >= 0);
	ATF_CHECK_EQ_MSG(0, bind(s_seq, (struct sockaddr *)&sun, slen),
	    "SOCK_SEQPACKET bind to same name should succeed: %s",
	    strerror(errno));

	/* Same name, same type: must still collide. */
	s_stream2 = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s_stream2 >= 0);
	ATF_REQUIRE_EQ(-1, bind(s_stream2, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(EADDRINUSE, errno);

	close(s_stream);
	close(s_dgram);
	close(s_seq);
	close(s_stream2);
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
	slen = mkabstract(&sun, "chmod_test", sizeof("chmod_test") - 1);
	ATF_REQUIRE_EQ(0, bind(s, (struct sockaddr *)&sun, slen));
	ATF_REQUIRE_EQ(-1, fchmod(s, 0600));
	ATF_REQUIRE_EQ(EINVAL, errno);
	close(s);
}

/*
 * Autobind: bind(2) with a length-1 abstract address (just the NUL marker,
 * no following bytes) triggers kernel-assigned name selection.  The kernel
 * picks a unique \0NNNNN name (NUL + 5 lowercase hex digits), binds the
 * socket to it, and getsockname(2) returns the assigned address.  Two
 * autobinds within the same prison and socket type must produce distinct
 * names.  The assigned address is usable for datagram exchange.
 */
ATF_TC_WITHOUT_HEAD(autobind);
ATF_TC_BODY(autobind, tc)
{
	struct sockaddr_un trigger, bound, bound2;
	socklen_t blen;
	int s1, s2, cs, i;
	char buf[1];

	/*
	 * Autobind trigger: sun_path[0] == '\0' and namelen == 1.
	 * sun_len = offsetof(sun_path) + 1.
	 */
	memset(&trigger, 0, sizeof(trigger));
	trigger.sun_family = AF_UNIX;
	trigger.sun_len = offsetof(struct sockaddr_un, sun_path) + 1;

	s1 = socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(s1 >= 0);
	ATF_REQUIRE_EQ(0, bind(s1, (struct sockaddr *)&trigger,
	    trigger.sun_len));

	/* getsockname must return a 6-byte abstract name: \0 + 5 hex digits. */
	blen = sizeof(bound);
	ATF_REQUIRE_EQ(0, getsockname(s1, (struct sockaddr *)&bound, &blen));
	ATF_REQUIRE_EQ((socklen_t)(offsetof(struct sockaddr_un, sun_path) + 6),
	    blen);
	ATF_REQUIRE_EQ('\0', bound.sun_path[0]);
	for (i = 1; i <= 5; i++)
		ATF_REQUIRE_MSG(isxdigit((unsigned char)bound.sun_path[i]),
		    "sun_path[%d] = 0x%02x is not a hex digit", i,
		    (unsigned char)bound.sun_path[i]);

	/* Second autobind must produce a distinct name (same type, same prison). */
	s2 = socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(s2 >= 0);
	ATF_REQUIRE_EQ(0, bind(s2, (struct sockaddr *)&trigger,
	    trigger.sun_len));
	blen = sizeof(bound2);
	ATF_REQUIRE_EQ(0, getsockname(s2, (struct sockaddr *)&bound2, &blen));
	ATF_REQUIRE_MSG(
	    memcmp(bound.sun_path, bound2.sun_path, 6) != 0,
	    "two autobinds produced the same name");

	/* The assigned address is reachable: another socket can send to it. */
	blen = offsetof(struct sockaddr_un, sun_path) + 6;
	cs = socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE_EQ(1, sendto(cs, "x", 1, 0,
	    (struct sockaddr *)&bound, blen));
	ATF_REQUIRE_EQ(1, recv(s1, buf, sizeof(buf), 0));
	ATF_REQUIRE_EQ('x', buf[0]);

	close(cs);
	close(s1);
	close(s2);
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
	ATF_TP_ADD_TC(tp, type_independence);
	ATF_TP_ADD_TC(tp, chmod_rejected);
	ATF_TP_ADD_TC(tp, autobind);
	return (atf_no_error());
}
