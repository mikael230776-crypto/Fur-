import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = {
    "review": ROOT / "docs" / "step8-uk-gdpr-review.md",
    "notice": ROOT / "docs" / "privacy-notice-draft.md",
    "retention": ROOT / "docs" / "data-retention-policy-draft.md",
    "terms": ROOT / "docs" / "business-terms-draft.md",
}


class Step8PrivacyDocumentsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = {name: path.read_text(encoding="utf-8") for name, path in DOCS.items()}

    def test_all_documents_exist_and_are_substantial(self):
        for name, path in DOCS.items():
            with self.subTest(document=name):
                self.assertTrue(path.is_file())
                self.assertGreater(len(self.text[name]), 1000)

    def test_every_document_is_clearly_a_draft(self):
        for name, text in self.text.items():
            with self.subTest(document=name):
                opening = text[:500].upper()
                self.assertIn("DRAFT", opening)
                self.assertIn("NOT LEGAL ADVICE", opening)
                self.assertTrue("DO NOT PUBLISH" in opening or "NOT FOR PUBLICATION" in opening or "NOT YET IMPLEMENTED" in opening or "DO NOT USE OR PUBLISH" in opening)

    def test_missing_legal_identity_is_not_hidden(self):
        combined = "\n".join(self.text.values()).upper()
        self.assertIn("CONTROLLER NAME", combined)
        self.assertIn("PRIVACY EMAIL", combined)
        self.assertIn("POSTAL ADDRESS", combined)
        self.assertGreaterEqual(combined.count("REQUIRED"), 12)

    def test_review_covers_core_uk_gdpr_controls(self):
        review = self.text["review"].lower()
        for required in (
            "lawful basis",
            "data minimisation",
            "retention",
            "individual rights",
            "dpia",
            "international transfers",
            "cookies",
            "children",
            "ico",
        ):
            with self.subTest(control=required):
                self.assertIn(required, review)

    def test_notice_contains_required_transparency_topics(self):
        notice = self.text["notice"].lower()
        for required in (
            "who we are",
            "information we may use",
            "why we use information",
            "sharing information",
            "international transfers",
            "how long we keep information",
            "your rights",
            "automated decisions",
            "complaints",
        ):
            with self.subTest(topic=required):
                self.assertIn(required, notice)

    def test_retention_schedule_has_controls_not_just_periods(self):
        retention = self.text["retention"].lower()
        for required in (
            "proposed schedule",
            "deletion process",
            "legal holds",
            "backups",
            "individual-rights handling",
            "explicit approval",
        ):
            with self.subTest(control=required):
                self.assertIn(required, retention)

    def test_business_terms_cover_material_risks(self):
        terms = self.text["terms"].lower()
        for required in (
            "verification result",
            "accounts, permissions and security",
            "suspension",
            "data protection",
            "confidentiality",
            "liability",
            "termination",
            "governing law",
            "professional review",
        ):
            with self.subTest(topic=required):
                self.assertIn(required, terms)

    def test_no_document_claims_final_approval(self):
        combined = "\n".join(self.text.values()).lower()
        for prohibited in ("legally approved", "lawyer approved", "ready to publish", "fully compliant"):
            with self.subTest(phrase=prohibited):
                self.assertNotIn(prohibited, combined)


if __name__ == "__main__":
    unittest.main()
