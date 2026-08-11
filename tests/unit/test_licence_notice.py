"""The copyright holder is stated, and the notice matches the metadata.

There was no copyright notice anywhere in this repository at all. `LICENSE`
carried the FSF's copyright on the licence *text*, and its appendix still read
`Copyright (C) <year>  <name of author>` — which is the template the appendix
tells you to copy, not a grant. So the licensor was whoever held copyright by
operation of law, and nothing published said who that was.

That is survivable for a hobby project and not for this one: the CLA exists so
the work can also be sold under a commercial licence, and the asset in that
transaction is the copyright. A downstream user also had no "appropriate legal
notices" to preserve under AGPL §5, and no one to ask for permission.

`LICENSE` itself stays verbatim. Editing the appendix in place would make the
file a non-exact copy of the AGPL, which is what licence detectors match
against — the notice belongs on the program, which is where the appendix says
to put it.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOLDER = "Linclaw Consulting AB"
# The registration number, not the name, is what identifies the company: two
# Swedish companies can share a name and cannot share this.
ORG_NR = "559074-9239"


def test_the_package_carries_a_copyright_notice():
    """In `src/cra/__init__.py`, so it ships inside the wheel. A notice that
    exists only in a README is absent from everything anyone installs."""
    src = (ROOT / "src" / "cra" / "__init__.py").read_text()
    assert re.search(rf"Copyright \(C\) 20\d\d {re.escape(HOLDER)}", src), src[:400]
    assert "GNU Affero General Public License" in src


def test_the_notice_and_the_metadata_agree_on_version_only():
    """The classic licensing defect, and the reason this file exists.

    `pyproject.toml` declares `AGPL-3.0-only`. The FSF's recommended notice
    says "version 3 of the License, or (at your option) any later version".
    Pasting it unedited would ship a package whose metadata promises one set of
    terms and whose source offers a wider one — and the wider one wins for
    anyone who reads the source, so the metadata would simply be wrong.
    """
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert 'license = "AGPL-3.0-only"' in pyproject

    src = (ROOT / "src" / "cra" / "__init__.py").read_text()
    assert "any later version" not in src, (
        "the notice offers later AGPL versions while the package metadata says "
        "`AGPL-3.0-only`. Change both or neither."
    )


def test_the_licence_file_is_left_verbatim():
    """Its appendix is a template to copy from, not a form to fill in. Editing
    it would break the byte-comparison licence detectors use, and the notice
    has a proper home in the package."""
    licence = (ROOT / "LICENSE").read_text()
    assert "Copyright (C) <year>  <name of author>" in licence
    assert HOLDER not in licence


def test_the_cla_names_a_legal_person():
    """It defined "The Project" as a URL and "its maintainer, Skarp" — which is
    the product name. A contributor was granting rights to something that was
    not a legal entity, which is precisely the grant the dual-licensing plan
    depends on."""
    cla = (ROOT / "CLA.md").read_text()
    assert HOLDER in cla


def test_the_public_pages_name_the_same_party():
    """Terms said "operated by Skarp"; the privacy page named Skarp as data
    controller and offered the legal entity on request. Under GDPR the
    controller's identity is not something a reader should have to ask for, and
    a different name on the site from the one in the licence is worse than
    either alone."""
    for page, needle in (("terms.html", "operated by"), ("privacy.html", "Controller")):
        html = (ROOT / "www" / page).read_text()
        assert HOLDER in html, f"{page} does not name the operator"
        assert needle in html


def test_the_controller_is_identified_rather_than_offered_on_request():
    """GDPR Art 13(1)(a) wants the controller's identity and contact details
    given, not available on application. The page used to name the product and
    offer the legal entity to anyone who asked, which is the wrong way round:
    the people least likely to ask are the ones the article is written for.
    """
    html = (ROOT / "www" / "privacy.html").read_text()
    assert HOLDER in html
    assert ORG_NR in html
    assert "Mariestad" in html
    assert "Sweden" in html
    # The old escape hatch. Leaving it beside a published address would read as
    # though something were still being withheld.
    assert "ask and we will provide it" not in html


def test_the_terms_name_the_same_company_as_the_licence():
    """A counterparty reading the terms and a contributor reading the CLA must
    end up at one legal person. Three files carried a party name and they were
    edited at different times, which is how they drift."""
    for path in ("www/terms.html", "CLA.md"):
        text = (ROOT / path).read_text()
        assert HOLDER in text, path
        assert ORG_NR in text, path
