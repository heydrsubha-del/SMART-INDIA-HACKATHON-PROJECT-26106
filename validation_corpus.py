"""Shared corpus. (kind, value, py_accept, sql_now, sql_new, category, note)
py_accept = indicator_sanitizer returns the value UNCHANGED (ok and value == input)  -> checked against the real module.
sql_now / sql_new = current exported SQL / proposed migration -> checked ONLY against sql_model.py (a Python model), never run on PostgreSQL.
Rule: py_accept != sql_new is allowed only for INTENTIONAL_*, GAP*, DEFERRED_* or SQL_WEAKER_UNFIXED rows."""
G65, G21 = "g" * 65, "g" * 21
R = [
 ("domain","example.com",1,1,1,"PARITY","existing valid"),
 ("domain","evil.example.net",1,1,1,"PARITY","existing valid"),
 ("domain","login.secure.example.com",1,1,1,"PARITY","readable subdomains"),
 ("domain","synthetic-abcdefgh-x.example.org",1,1,1,"PARITY","readable hyphenated label (existing test value)"),
 ("domain","authentication.example.com",1,1,1,"PARITY","readable, 14 chars (never flagged)"),
 ("domain","internationalization.example.com",1,1,1,"PARITY","READABLE PRESERVED: 20 letters, readable-word exception"),
 ("domain","telecommunications.example.com",1,1,1,"PARITY","READABLE PRESERVED"),
 ("domain","characteristically.example.com",1,1,1,"PARITY","READABLE PRESERVED (y counted as vowel)"),
 ("domain","misunderstandings.example.com",1,1,1,"PARITY","READABLE PRESERVED (was rejected by the old vowel-ratio rule)"),
 ("domain","straightforwardness.example.com",1,1,1,"PARITY","READABLE PRESERVED (was rejected by the old consonant-run rule)"),
 ("domain","accountverification.example.com",1,1,1,"PARITY","READABLE PRESERVED: concatenated English words"),
 ("domain","customersupportcenter.example.com",1,1,1,"PARITY","READABLE PRESERVED: concatenated English words"),
 ("domain","bhalobasarmanushjon.example.com",1,1,1,"PARITY","transliterated Bengali that passes BY CHANCE of its letter pairs: the rule is not a language check"),
 ("domain","dhanyavadsabhikaryakram.example.com",1,1,0,"INTENTIONAL_STRICTER_SQL","transliterated Hindi: Python accepts, SQL rejects (too few common English pairs); fails closed"),
 ("domain","aabbccddeeffgghhii.example.com",1,1,0,"INTENTIONAL_STRICTER_SQL","repeated-pattern letters: low entropy, not English-like"),
 ("domain","internationalization2.example.com",1,1,0,"INTENTIONAL_STRICTER_SQL","letters+digit label: exception is letters-only"),
 ("domain","qwertyuiopasdfghjkl.example.com",0,1,0,"GAP1_CLOSED","keyboard-walk label"),
 ("domain",G21+".example.com",1,1,0,"INTENTIONAL_STRICTER_SQL","one repeated letter: Python's entropy rule alone would allow it"),
 ("domain","x9f3kq2m7a1b.example.com",0,1,0,"GAP1_CLOSED","random subdomain (digits)"),
 ("domain","qzxkvbnmplwjhgfdsa.example.com",0,1,0,"GAP1_CLOSED","random letters-only subdomain, high entropy"),
 ("domain","deadbeefdeadbeefdead.example.com",0,1,0,"GAP1_CLOSED","hex-only subdomain"),
 ("domain","123e4567-e89b-12d3-a456-426614174000.example.com",0,1,0,"GAP1_CLOSED","uuid subdomain"),
 ("domain","xn--80ak6aa92e.example.com",0,1,0,"GAP1_CLOSED","punycode subdomain label counts as token in BOTH"),
 ("domain","x9f3kq2m7a1b.example.co.uk",0,1,0,"GAP1_CLOSED","two-part suffix: label left of example.co.uk"),
 ("domain","x9f3kq2m7a1b.co.uk",1,1,1,"PARITY","two-part suffix: registrable label is not checked"),
 ("domain","x9f3kq2m7a1b.com",1,1,1,"PARITY","random registrable domain stays shareable"),
 ("domain","shop.example.com.au",1,1,1,"PARITY","two-part suffix, readable"),
 ("domain","x9f3kq2m7a1b.shop.example.com.au",0,1,0,"GAP1_CLOSED","two-part suffix, random subdomain"),
 ("url","https://example.com/",1,1,1,"PARITY","existing valid"),
 ("url","http://evil.example.net/login",1,1,1,"PARITY","existing valid"),
 ("url","http://internationalization.example.com/login",1,1,1,"PARITY","READABLE PRESERVED in a URL host"),
 ("url","http://example.com/reset-password/step-2",1,1,1,"PARITY","readable segments"),
 ("url","http://example.com/a/123e4567-e89b-12d3-a456-426614174000",0,0,0,"PARITY","uuid path: Python truncates (not as-is), SQL rejects, never rewrites"),
 ("url","http://example.com/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",0,0,0,"PARITY","jwt path"),
 ("url","http://example.com/"+G65,0,0,0,"PARITY","segment > 64 chars"),
 ("url","http://example.com/x7k2m9q4w8z1/x7k2m9q4w8z1/x7k2m9q4w8z1",0,0,0,"PARITY","repeated token-like segments"),
 ("url","http://example.com/internationalization",1,0,0,"INTENTIONAL_STRICTER_SQL","path segments keep looks_like_token's strict 16+ rule (unchanged, no exception)"),
 ("url","http://example.com/a%20b",1,0,0,"INTENTIONAL_STRICTER_SQL","SQL forbids % escapes; Python keeps them"),
 ("url","http://example.com:8080/x",0,0,0,"PARITY","port"),
 ("url","http://example.com/x?t=1",0,0,0,"PARITY","query"),
 ("url","http://x9f3kq2m7a1b.example.com/login",0,1,0,"GAP1_CLOSED","random subdomain in URL host"),
 ("url","http://8.8.4.4/login",1,1,1,"PARITY","public IPv4 host"),
 ("url","http://10.0.0.1/login",0,0,0,"PARITY","private IPv4 host"),
 ("url","http://[2606:4700:4700::1111]/login",1,0,0,"DEFERRED_IPV6_URL","Python accepts, SQL still rejects: separate proposal"),
 ("url","http://[::1]/",0,0,0,"PARITY","loopback IPv6 URL"),
 ("ip","8.8.4.4",1,1,1,"PARITY","existing valid"),
 ("ip","2606:4700:4700::1111",1,1,1,"PARITY","existing valid"),
 ("ip","10.0.0.1",0,0,0,"PARITY","private"),
 ("ip","2002:808:808::1",0,1,1,"SQL_WEAKER_UNFIXED","6to4: Python rejects, is_public_ip allows (not in approved design)"),
 ("ip","2001::1",0,1,1,"SQL_WEAKER_UNFIXED","Teredo: same"),
 ("hash","d41d8cd98f00b204e9800998ecf8427e",1,1,1,"PARITY","existing valid"),
 ("hash","D41D8CD98F00B204E9800998ECF8427E",0,0,0,"PARITY","upper-case hash"),
]
def _sql_literal(value):
    if not isinstance(value, str):
        raise TypeError("SQL text values must be strings")
    return "'" + value.replace("'", "''") + "'"


def render_sql():
    b = lambda x: "true" if x else "false"
    rows = ",\n".join(
        "  (%s,%s,%s,%s,%s)" % (  # nosec B608: fixed corpus; text is quoted and output is not executed here.
            _sql_literal(k), _sql_literal(v), b(n), b(w), _sql_literal(c)
        )
        for k, v, _, n, w, c, _x in R
    )
    return ("-- READ-ONLY validation checks: pure function calls, no writes, no temp objects. NOT RUN. Only for algorithmistic-test, after approval.\n"
            "-- 'baseline' = expected result of the CURRENT exported functions; 'expected' = expected after the proposed migration.\n"
            "-- Before applying: rows where actual <> baseline mean my reading of the exports is wrong. After applying: every row must show pass = true.\n"
            "-- Expected changes vs baseline are exactly the GAP1_CLOSED and INTENTIONAL/readable rows that flip (domain/URL-host subdomain labels).\n"
            "select kind, left(val, 60) as val, baseline, expected, category,\n"
            "       private.valid_indicator(kind, val) as actual,\n"
            "       private.valid_indicator(kind, val) = expected as pass\n"
            "from (values\n" + rows + "\n) as t(kind, val, baseline, expected, category)\n"
            "order by pass, category;\n")
