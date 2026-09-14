"""Evidence verification: does the code the model quoted actually exist?

The matcher is the only thing standing between "the model said so" and a line
range we put in SARIF, so these tests pin both directions: what it must match
through (whitespace, blank lines, read_file's gutter) and what it must refuse
(paraphrased code, paths outside the sandbox).
"""

from __future__ import annotations

import json

import pytest

from stride_gpt.agent.evidence import (
    MAX_COMMENT_SKIP,
    MAX_SNIPPET_CHARS,
    EvidenceCheck,
    normalise_path,
    summarise_checks,
    verify_evidence,
    verify_one,
)
from stride_gpt.agent.tools import read_file

AUTH = "src/auth.py"
AUTH_BODY = "def login(user, password):\n    return check_db(user, password)"


class TestMatches:
    def test_exact_multi_line(self, sandbox_dir):
        check = verify_one(sandbox_dir, AUTH, AUTH_BODY)
        assert check.verified
        assert (check.start_line, check.end_line) == (1, 2)
        assert check.reason is None

    def test_single_line(self, sandbox_dir):
        check = verify_one(sandbox_dir, AUTH, "    return check_db(user, password)")
        assert (check.verified, check.start_line, check.end_line) == (True, 2, 2)

    def test_fragment_of_a_longer_line(self, sandbox_dir):
        """A model quoting the call out of the middle of a line still matches."""
        check = verify_one(sandbox_dir, AUTH, "check_db(user, password)")
        assert (check.verified, check.start_line) == (True, 2)

    @pytest.mark.parametrize(
        "snippet",
        [
            pytest.param(
                "def login(user, password):\n        return check_db(user, password)",
                id="reindented",
            ),
            pytest.param(
                "def login(user, password):\n\treturn check_db(user, password)",
                id="tabs",
            ),
            pytest.param(
                "def  login(user,  password):\n    return check_db(user, password)   ",
                id="inner-and-trailing-space",
            ),
            pytest.param(
                "def login(user, password):\n\n    return check_db(user, password)",
                id="blank-line-inserted",
            ),
        ],
    )
    def test_whitespace_differences_are_tolerated(self, sandbox_dir, snippet):
        assert verify_one(sandbox_dir, AUTH, snippet).verified

    def test_blank_line_dropped_by_the_model(self, sandbox_dir):
        """crlf.py has a blank line the model didn't reproduce."""
        check = verify_one(sandbox_dir, "crlf.py", "import os\ndef run(cmd):")
        assert check.verified
        # The range spans the blank line, which is the region worth showing.
        assert (check.start_line, check.end_line) == (1, 3)

    def test_crlf_file(self, sandbox_dir):
        check = verify_one(sandbox_dir, "crlf.py", "def run(cmd):\n    os.system(cmd)")
        assert (check.verified, check.start_line, check.end_line) == (True, 3, 4)

    def test_read_file_gutter_is_stripped(self, sandbox_dir):
        """Models copy read_file output wholesale, gutter included."""
        check = verify_one(
            sandbox_dir, AUTH, "1\tdef login(user, password):\n2\t    return check_db(user, password)"
        )
        assert (check.verified, check.start_line, check.end_line) == (True, 1, 2)

    def test_gutter_not_stripped_when_numbers_are_not_consecutive(self, sandbox_dir):
        """Tab-separated data must not be mistaken for a gutter."""
        (sandbox_dir / "data.tsv").write_text("1\talpha\n7\tbeta\n")
        check = verify_one(sandbox_dir, "data.tsv", "1\talpha\n7\tbeta")
        assert check.verified

    def test_gutter_with_a_bare_blank_line(self, sandbox_dir):
        """A model copying read_file output writes the blank line bare, so the
        numbers jump. The strict check reads that as "not line numbers"; a
        lenient retry catches it once the strict reading has failed."""
        (sandbox_dir / "gap.py").write_text("a = 0\ndef f():\n\n    return 1\n")
        check = verify_one(sandbox_dir, "gap.py", "2\tdef f():\n\n4\t    return 1")
        assert (check.verified, check.start_line, check.end_line) == (True, 2, 4)

    def test_lenient_retry_does_not_override_a_strict_match(self, sandbox_dir):
        """Data that merely looks like a gutter still matches as data."""
        (sandbox_dir / "tsv2.tsv").write_text("1\talpha\n7\tbeta\n")
        check = verify_one(sandbox_dir, "tsv2.tsv", "1\talpha\n7\tbeta")
        assert (check.verified, check.start_line, check.end_line) == (True, 1, 2)

    def test_markdown_fence_is_stripped(self, sandbox_dir):
        check = verify_one(sandbox_dir, AUTH, f"```python\n{AUTH_BODY}\n```")
        assert check.verified

    def test_backslash_path_form(self, sandbox_dir):
        assert verify_one(sandbox_dir, "src\\auth.py", AUTH_BODY).verified

    def test_leading_dot_slash_path(self, sandbox_dir):
        check = verify_one(sandbox_dir, "./src/auth.py", AUTH_BODY)
        assert check.verified
        assert check.path == AUTH

    def test_repeated_snippet_reports_first_and_counts(self, sandbox_dir):
        (sandbox_dir / "dup.py").write_text("x = 1\ny = 2\nx = 1\n")
        check = verify_one(sandbox_dir, "dup.py", "x = 1")
        assert (check.verified, check.start_line, check.occurrences) == (True, 1, 2)
        assert check.to_dict()["occurrences"] == 2


class TestElidedComments:
    """Models quote a function body and drop its comments.

    That is still a faithful quote of the code, and refusing it marked most
    real citations from a commented codebase unverified.
    """

    @pytest.fixture
    def commented(self, sandbox_dir):
        (sandbox_dir / "commented.py").write_text(
            "def charge(amount):\n"
            "    # Trust the client-supplied amount.\n"
            "    # TODO: revalidate against the order.\n"
            "    return bill(amount)\n"
        )
        return sandbox_dir

    def test_dropped_comments_still_match(self, commented):
        check = verify_one(
            commented, "commented.py", "def charge(amount):\n    return bill(amount)"
        )
        assert check.verified
        # The range spans the comments, which is the region worth showing.
        assert (check.start_line, check.end_line) == (1, 4)

    def test_quoted_comments_still_match(self, commented):
        check = verify_one(
            commented,
            "commented.py",
            "def charge(amount):\n    # Trust the client-supplied amount.\n"
            "    # TODO: revalidate against the order.\n    return bill(amount)",
        )
        assert (check.verified, check.start_line, check.end_line) == (True, 1, 4)

    @pytest.mark.parametrize(
        "marker", ["#", "//", "/*", "*", "*/", "<!--", "--", ";"]
    )
    def test_comment_markers(self, sandbox_dir, marker):
        (sandbox_dir / "c.txt").write_text(f"first line\n{marker} a comment\nsecond line\n")
        check = verify_one(sandbox_dir, "c.txt", "first line\nsecond line")
        assert (check.verified, check.start_line, check.end_line) == (True, 1, 3)

    def test_a_dropped_code_line_is_still_refused(self, sandbox_dir):
        """Only comments are skippable. Eliding real code is not quoting it."""
        (sandbox_dir / "gap.py").write_text("a = 1\nb = 2\nc = 3\n")
        assert not verify_one(sandbox_dir, "gap.py", "a = 1\nc = 3").verified

    def test_too_many_elided_comments_is_refused(self, sandbox_dir):
        """Past the cap the model is stitching two passages together, not
        quoting one."""
        body = "\n".join(f"# comment {i}" for i in range(MAX_COMMENT_SKIP + 1))
        (sandbox_dir / "wall.py").write_text(f"start = 1\n{body}\nend = 2\n")
        assert not verify_one(sandbox_dir, "wall.py", "start = 1\nend = 2").verified

    def test_just_within_the_cap_matches(self, sandbox_dir):
        body = "\n".join(f"# comment {i}" for i in range(MAX_COMMENT_SKIP))
        (sandbox_dir / "ok.py").write_text(f"start = 1\n{body}\nend = 2\n")
        assert verify_one(sandbox_dir, "ok.py", "start = 1\nend = 2").verified

    def test_a_trailing_comment_is_not_part_of_the_range(self, commented):
        """The range ends at the last matched code line, not at a comment
        that happened to follow it."""
        check = verify_one(commented, "commented.py", "def charge(amount):")
        assert (check.start_line, check.end_line) == (1, 1)

class TestRefuses:
    def test_snippet_not_in_file(self, sandbox_dir):
        check = verify_one(sandbox_dir, AUTH, "def login(user):\n    return True")
        assert not check.verified
        assert "not found" in check.reason
        assert check.start_line is None

    def test_paraphrased_code_is_not_a_quote(self, sandbox_dir):
        """Whitespace is forgiven; rewriting the code is not."""
        assert not verify_one(sandbox_dir, AUTH, "def Login(user, password):").verified

    @pytest.mark.parametrize("path", ["../../etc/passwd", ".git/HEAD", "src/../.git/HEAD"])
    def test_outside_the_sandbox(self, sandbox_dir, path):
        check = verify_one(sandbox_dir, path, "anything")
        assert not check.verified
        assert "denied" in check.reason

    def test_missing_file(self, sandbox_dir):
        check = verify_one(sandbox_dir, "nope.py", "x = 1")
        assert (check.verified, check.reason) == (False, "not a file in the analysed codebase")

    def test_directory_path(self, sandbox_dir):
        assert not verify_one(sandbox_dir, "src", "x = 1").verified

    @pytest.mark.parametrize("snippet", ["", "   ", "\n\n"])
    def test_empty_snippet(self, sandbox_dir, snippet):
        check = verify_one(sandbox_dir, AUTH, snippet)
        assert (check.verified, check.reason) == (False, "snippet is empty")

    def test_oversized_snippet_is_refused_not_truncated(self, sandbox_dir):
        check = verify_one(sandbox_dir, AUTH, "x" * (MAX_SNIPPET_CHARS + 1))
        assert not check.verified
        assert "too long" in check.reason

    def test_file_over_the_verify_cap(self, sandbox_dir, monkeypatch):
        monkeypatch.setattr("stride_gpt.agent.evidence.MAX_VERIFY_BYTES", 10)
        check = verify_one(sandbox_dir, AUTH, AUTH_BODY)
        assert (check.verified, check.reason) == (False, "file is too large to verify")


class TestVerifyEvidence:
    def test_list_of_items(self, sandbox_dir):
        checks = verify_evidence(
            sandbox_dir,
            [
                {"path": AUTH, "snippet": AUTH_BODY},
                {"path": "config.yaml", "snippet": "nope: false"},
            ],
        )
        assert [c.verified for c in checks] == [True, False]

    def test_double_encoded_json_string(self, sandbox_dir):
        raw = json.dumps([{"path": AUTH, "snippet": AUTH_BODY}])
        assert [c.verified for c in verify_evidence(sandbox_dir, raw)] == [True]

    def test_single_dict_is_accepted(self, sandbox_dir):
        assert len(verify_evidence(sandbox_dir, {"path": AUTH, "snippet": AUTH_BODY})) == 1

    @pytest.mark.parametrize("raw", [None, "not json", 42, [], [None, 7]])
    def test_junk_yields_no_checks(self, sandbox_dir, raw):
        assert verify_evidence(sandbox_dir, raw) == []

    def test_item_missing_a_field(self, sandbox_dir):
        (check,) = verify_evidence(sandbox_dir, [{"path": AUTH}])
        assert not check.verified
        assert "needs a 'path' string" in check.reason

    def test_max_items(self, sandbox_dir):
        items = [{"path": AUTH, "snippet": AUTH_BODY}] * 9
        assert len(verify_evidence(sandbox_dir, items, max_items=3)) == 3


class TestSerialisation:
    def test_verified_shape(self):
        d = EvidenceCheck(path="a.py", snippet="x", verified=True, start_line=3, end_line=5).to_dict()
        assert d == {"path": "a.py", "snippet": "x", "verified": True, "start_line": 3, "end_line": 5}

    def test_unverified_shape(self):
        d = EvidenceCheck(path="a.py", snippet="x", verified=False, reason="nope").to_dict()
        assert d == {"path": "a.py", "snippet": "x", "verified": False, "reason": "nope"}

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("./src/a.py", "src/a.py"), ("/src/a.py", "src/a.py"), ("src\\a.py", "src/a.py"),
         (None, ""), ("  a.py ", "a.py")],
    )
    def test_normalise_path(self, value, expected):
        assert normalise_path(value) == expected


class TestSummarise:
    def test_all_verified(self, sandbox_dir):
        text = summarise_checks(verify_evidence(sandbox_dir, [{"path": AUTH, "snippet": AUTH_BODY}]))
        assert "src/auth.py lines 1-2 verified" in text
        assert "NOT verified" not in text

    def test_mixed_tells_the_model_the_threat_survived(self, sandbox_dir):
        text = summarise_checks(
            verify_evidence(
                sandbox_dir,
                [{"path": AUTH, "snippet": AUTH_BODY}, {"path": AUTH, "snippet": "zzz"}],
            )
        )
        assert "NOT verified" in text
        assert "kept" in text
        assert "Do not re-report" in text

    def test_no_evidence(self):
        assert "No evidence" in summarise_checks([])

    def test_single_line_range_reads_as_one_line(self, sandbox_dir):
        text = summarise_checks(
            verify_evidence(sandbox_dir, [{"path": "crlf.py", "snippet": "import os"}])
        )
        assert "crlf.py line 1 verified" in text


def test_line_numbers_agree_with_read_file(sandbox_dir):
    """The range we report must be the range read_file returns.

    Both sides split with ``splitlines()``; this pins that contract, because a
    drift here puts a wrong region in SARIF.
    """
    check = verify_one(sandbox_dir, AUTH, AUTH_BODY)
    out = read_file(sandbox_dir, AUTH, check.start_line, check.end_line)
    body = out.split("\n\n", 1)[1]
    quoted = [line.split("\t", 1)[1] for line in body.split("\n")]
    assert quoted == AUTH_BODY.split("\n")
