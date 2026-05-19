# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Ricardo Branco <rbranco@suse.de>
#
# Tests for optional backup suffix in -i and -I.
# See PR 254091.

atf_test_case i_attached_suffix
i_attached_suffix_head() {
	atf_set "descr" "sed -i.bak creates a backup with the attached suffix"
}
i_attached_suffix_body() {
	printf 'old\n' > f
	atf_check sed -i.bak 's/old/new/' f
	atf_check -o inline:'new\n' cat f
	atf_check -o inline:'old\n' cat f.bak
}

atf_test_case i_empty_idiom
i_empty_idiom_head() {
	atf_set "descr" "sed -i '' performs in-place edit without backup (legacy FreeBSD idiom)"
}
i_empty_idiom_body() {
	printf 'old\n' > f
	atf_check sed -i '' 's/old/new/' f
	atf_check -o inline:'new\n' cat f
	atf_check -o empty -e empty sh -c 'ls f.* 2>/dev/null || true'
}

atf_test_case i_no_suffix
i_no_suffix_head() {
	atf_set "descr" "sed -i with no suffix performs in-place edit without backup (PR 254091)"
}
i_no_suffix_body() {
	printf 'old\n' > f
	atf_check sed -i 's/old/new/' f
	atf_check -o inline:'new\n' cat f
	atf_check -o empty -e empty sh -c 'ls f.* 2>/dev/null || true'
}

atf_test_case i_space_separated_suffix
i_space_separated_suffix_head() {
	atf_set "descr" "sed -i .bak (space-separated) creates a backup with .bak"
}
i_space_separated_suffix_body() {
	printf 'old\n' > f
	atf_check sed -i .bak 's/old/new/' f
	atf_check -o inline:'new\n' cat f
	atf_check -o inline:'old\n' cat f.bak
}

atf_test_case i_with_e_flag
i_with_e_flag_head() {
	atf_set "descr" "sed -i followed by -e is unambiguous: no suffix"
}
i_with_e_flag_body() {
	printf 'old\n' > f
	atf_check sed -i -e 's/old/new/' f
	atf_check -o inline:'new\n' cat f
	atf_check -o empty -e empty sh -c 'ls f.* 2>/dev/null || true'
}

atf_test_case i_multiple_files
i_multiple_files_head() {
	atf_set "descr" "sed -i edits each file independently (no span across inputs)"
}
i_multiple_files_body() {
	printf '1\n' > a
	printf '2\n' > b
	atf_check sed -i 's/^/x/' a b
	atf_check -o inline:'x1\n' cat a
	atf_check -o inline:'x2\n' cat b
}

atf_test_case I_attached_suffix
I_attached_suffix_head() {
	atf_set "descr" "sed -I.bak creates a backup with the attached suffix"
}
I_attached_suffix_body() {
	printf 'old\n' > f
	atf_check sed -I.bak 's/old/new/' f
	atf_check -o inline:'new\n' cat f
	atf_check -o inline:'old\n' cat f.bak
}

atf_test_case I_empty_idiom
I_empty_idiom_head() {
	atf_set "descr" "sed -I '' performs in-place edit without backup"
}
I_empty_idiom_body() {
	printf 'old\n' > f
	atf_check sed -I '' 's/old/new/' f
	atf_check -o inline:'new\n' cat f
	atf_check -o empty -e empty sh -c 'ls f.* 2>/dev/null || true'
}

atf_test_case I_no_suffix
I_no_suffix_head() {
	atf_set "descr" "sed -I with no suffix performs in-place edit without backup"
}
I_no_suffix_body() {
	printf 'old\n' > f
	atf_check sed -I 's/old/new/' f
	atf_check -o inline:'new\n' cat f
	atf_check -o empty -e empty sh -c 'ls f.* 2>/dev/null || true'
}

atf_test_case I_space_separated_suffix
I_space_separated_suffix_head() {
	atf_set "descr" "sed -I .bak (space-separated) creates a backup with .bak"
}
I_space_separated_suffix_body() {
	printf 'old\n' > f
	atf_check sed -I .bak 's/old/new/' f
	atf_check -o inline:'new\n' cat f
	atf_check -o inline:'old\n' cat f.bak
}

atf_test_case I_spans_input
I_spans_input_head() {
	atf_set "descr" "sed -I treats inputs as a single stream; addresses span files"
}
I_spans_input_body() {
	printf '1\n2\n' > a
	printf '3\n4\n' > b
	# Address '3' should match the 3rd line of the joined stream,
	# which lives in file 'b'. With -i (no span) it would match
	# line 3 of each file independently.
	atf_check sed -I '3s/^/X/' a b
	atf_check -o inline:'1\n2\n' cat a
	atf_check -o inline:'X3\n4\n' cat b
}

atf_init_test_cases() {
	atf_add_test_case i_attached_suffix
	atf_add_test_case i_empty_idiom
	atf_add_test_case i_no_suffix
	atf_add_test_case i_space_separated_suffix
	atf_add_test_case i_with_e_flag
	atf_add_test_case i_multiple_files
	atf_add_test_case I_attached_suffix
	atf_add_test_case I_empty_idiom
	atf_add_test_case I_no_suffix
	atf_add_test_case I_space_separated_suffix
	atf_add_test_case I_spans_input
}
