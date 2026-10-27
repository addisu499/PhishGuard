import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine import analyze
from engine.common import levenshtein, registered_domain

LOGIN_CLONE = """<html><head><title>PayPal - Log in</title></head><body>
<img alt="PayPal logo" src="logo.png"><form action="https://evil.example.net/c">
<input type="email"><input type="password"></form></body></html>"""


class UrlTests(unittest.TestCase):
    def verdict(self, url, html=None):
        return analyze(url, html)["verdict"]

    def test_official_domains_safe(self):
        for u in ["https://www.paypal.com/signin", "https://cbe.com.et/", "https://accounts.google.com/login"]:
            self.assertEqual(self.verdict(u), "safe", u)

    def test_homoglyph_dangerous(self):
        self.assertEqual(self.verdict("https://paypa1.com/login"), "dangerous")

    def test_typosquat_flagged(self):
        self.assertNotEqual(self.verdict("https://awashbamk.com/"), "safe")

    def test_ip_login_flagged(self):
        self.assertNotEqual(self.verdict("http://192.168.4.5/cbe/login"), "safe")

    def test_shortener_alone_is_not_dangerous(self):
        self.assertEqual(self.verdict("https://bit.ly/abc"), "safe")

    def test_plain_site_safe(self):
        self.assertEqual(self.verdict("https://example.com/"), "safe")


class RegressionTests(unittest.TestCase):
    """False positives found in the first PhishTank/Tranco evaluation run."""
    def test_country_domain_of_big_brand_not_flagged(self):
        self.assertEqual(analyze("https://google.fr/")["verdict"], "safe")

    def test_brand_owned_tld_not_flagged(self):
        self.assertEqual(analyze("https://usgovcloud-core.microsoft/")["verdict"], "safe")

    def test_local_brand_wrong_suffix_still_flagged(self):
        self.assertNotEqual(analyze("https://cbe.com/")["verdict"], "safe")


class LexicalTests(unittest.TestCase):
    def names(self, url):
        return [x["name"] for x in analyze(url)["signals"]]

    def test_free_hosting_subdomain(self):
        self.assertIn("free_hosting_subdomain", self.names("https://secure-login.pages.dev/"))

    def test_plain_hosting_root_not_flagged(self):
        self.assertNotIn("free_hosting_subdomain", self.names("https://github.io/"))

    def test_risky_tld_alone_is_not_enough(self):
        self.assertEqual(analyze("https://bakery.shop/")["verdict"], "safe")

    def test_gibberish_domain(self):
        self.assertIn("gibberish_domain", self.names("https://fsdfsgfscssdgbq.com/"))

    def test_stacked_weak_signals_flag(self):
        self.assertNotEqual(analyze("https://xkqzrtpvbn1234.top/payment/login")["verdict"], "safe")

    def test_normal_big_sites_safe(self):
        for u in ["https://www.bbc.co.uk/", "https://stackoverflow.com/", "https://www.nytimes.com/"]:
            self.assertEqual(analyze(u)["verdict"], "safe", u)


class LocalBrandTests(unittest.TestCase):
    def test_local_brand_label_in_hostname(self):
        for u in ["https://awashbank-login-secure.com/verify", "https://secure-dashenbanksc.xyz/account/update"]:
            self.assertNotEqual(analyze(u)["verdict"], "safe", u)

    def test_hyphenated_keyword_mpesa(self):
        self.assertNotEqual(analyze("https://my-m-pesa.cfd/payment")["verdict"], "safe")

    def test_generic_word_site_not_flagged(self):
        for u in ["https://office-supplies-store.com/", "https://live-sports.com/"]:
            self.assertEqual(analyze(u)["verdict"], "safe", u)


class NewContentFeatureTests(unittest.TestCase):
    def names(self, url, html):
        return [x["name"] for x in analyze(url, html)["signals"]]

    def test_link_text_mismatch_detected(self):
        html = '<a href="https://evil.example.net/x">https://www.paypal.com/login</a>'
        self.assertIn("link_text_mismatch", self.names("https://blog.example.org/", html))

    def test_link_text_matching_destination_ok(self):
        html = '<a href="https://www.paypal.com/help">paypal.com</a><a href="/about">about.html</a>'
        self.assertNotIn("link_text_mismatch", self.names("https://blog.example.org/", html))

    def test_login_on_risky_url(self):
        html = "<title>Welcome</title><form><input type=password></form>"
        r = analyze("https://secure-portal.pages.dev/", html)
        self.assertIn("login_on_risky_url", [x["name"] for x in r["signals"]])
        self.assertNotEqual(r["verdict"], "safe")

    def test_plain_login_on_clean_url_not_flagged(self):
        html = "<title>Sign in</title><form><input type=email><input type=password></form>"
        self.assertEqual(analyze("https://shop.example.com/login", html)["verdict"], "safe")

    def test_local_brand_named_on_login_page(self):
        html = "<title>Notice</title><p>CBE customers: your CBE account needs review.</p><form><input type=password></form>"
        r = analyze("https://notice.example.org/", html)
        self.assertIn("brand_mention_with_login", [x["name"] for x in r["signals"]])

    def test_brand_named_without_login_not_flagged(self):
        html = "<title>News</title><p>CBE announced results. CBE said more.</p>"
        self.assertNotIn("brand_mention_with_login", self.names("https://news.example.org/", html))


class ContentTests(unittest.TestCase):
    def test_clone_is_dangerous(self):
        r = analyze("https://secure-pay.example.com/login", LOGIN_CLONE)
        self.assertEqual(r["verdict"], "dangerous")
        self.assertIn("brand_mismatch", [s["name"] for s in r["signals"]])

    def test_news_article_mentioning_brand_not_dangerous(self):
        r = analyze("https://news.example.com/", "<title>PayPal fined</title><p>text</p>")
        self.assertNotEqual(r["verdict"], "dangerous")

    def test_legit_page_on_official_domain(self):
        r = analyze("https://www.paypal.com/signin", LOGIN_CLONE.replace("evil.example.net", "www.paypal.com"))
        self.assertEqual(r["verdict"], "safe")

    def test_official_domain_posting_elsewhere_flagged(self):
        r = analyze("https://www.paypal.com/signin", LOGIN_CLONE)
        self.assertNotEqual(r["verdict"], "safe")

    def test_csrf_hidden_input_ignored(self):
        html = '<form action="/go"><input type="hidden" name="csrf"><input type="password"></form>'
        names = [s["name"] for s in analyze("https://shop.example.com/login", html)["signals"]]
        self.assertNotIn("offscreen_fields", names)

    def test_offscreen_field_flagged(self):
        html = '<form><input type="text" style="position:absolute;left:-9999px"></form>'
        names = [s["name"] for s in analyze("https://x.example.com/", html)["signals"]]
        self.assertIn("offscreen_fields", names)

    def test_malformed_html_does_not_crash(self):
        analyze("https://x.example.com/", "<form><input <<< </div>")


class LocalTests(unittest.TestCase):
    def test_amharic_phrase_detected(self):
        r = analyze("https://x.example.com/", "<p>መለያዎ ታግዷል ወዲያውኑ ያረጋግጡ</p>")
        self.assertIn("scam_phrasing", [s["name"] for s in r["signals"]])

    def test_clean_text_no_phrase(self):
        r = analyze("https://x.example.com/", "<p>Welcome to our bakery</p>")
        self.assertNotIn("scam_phrasing", [s["name"] for s in r["signals"]])


class PhraseTests(unittest.TestCase):
    def names(self, html):
        return [x["name"] for x in analyze("https://portal.example.org/", html)["signals"]]

    def test_credential_wording_alone_not_flagged(self):
        self.assertNotIn("scam_phrasing", self.names("<p>የይለፍ ቃልዎን ያስገቡ</p>"))

    def test_verify_wording_alone_not_flagged(self):
        self.assertNotIn("scam_phrasing", self.names("<p>Please verify your account email.</p>"))

    def test_new_amharic_prize_phrase(self):
        self.assertIn("scam_phrasing", self.names("<p>እድለኛ ሆነዋል! የገንዘብ ሽልማት</p>"))

    def test_telecom_bonus_wording(self):
        self.assertIn("scam_phrasing", self.names("<p>Free airtime for you. Act now!</p>"))

    def test_pressure_plus_context_scores_higher(self):
        a = analyze("https://portal.example.org/", "<p>Act now. Free airtime</p>")["score"]
        b = analyze("https://portal.example.org/", "<p>Act now. Free airtime. Enter your PIN</p>")["score"]
        self.assertGreater(b, a)


class InternationalizedDomainTests(unittest.TestCase):
    def test_plain_cyrillic_domain_not_flagged(self):
        self.assertEqual(analyze("https://xn--d1acpjx3f.xn--p1ai/")["verdict"], "safe")

    def test_false_positive_from_evaluation_fixed(self):
        self.assertEqual(analyze("https://xn---43-6cdjqynqkkvibxf.xn--p1ai/")["verdict"], "safe")

    def test_mixed_script_lookalike_flagged(self):
        host = "\u0440\u0430ypal.com".encode("idna").decode("ascii")   # Cyrillic p and a + Latin 'ypal'
        r = analyze("https://" + host + "/login")
        self.assertNotEqual(r["verdict"], "safe")
        self.assertIn("mixed_script", [x["name"] for x in r["signals"]])


class HelperTests(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(levenshtein("kitten", "sitting"), 3)

    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.cbe.com.et"), "cbe.com.et")
        self.assertEqual(registered_domain("www.paypal.com"), "paypal.com")


if __name__ == "__main__":
    unittest.main()
