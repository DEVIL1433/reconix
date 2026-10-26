"""Plain-language explanations for findings: 1-2 simple lines per
vulnerability type, shown next to the technical details so a non-expert
can understand what the finding means."""

_RULES = [
    (("attack chain",),
     "On its own each bug here looks small. Linked together they form a "
     "working attack path — the way a real intruder would actually get "
     "in — so together they deserve more urgency than any one of them "
     "alone."),
    (("business logic", "workflow step", "one-time step", "tampering accepted"),
     "The app's rules of business can be cheated: steps can be skipped, "
     "one-time offers used again and again, or prices changed on the "
     "way to the till. The computer checks the shape of the request, "
     "but not whether the deal makes sense."),
    (("another user", "bola"),
     "One logged-in user can see another user's private pages or data. "
     "The site checks that you are logged in, but not that the thing "
     "you asked for is yours."),
    (("api data accessible",),
     "A data feed meant for logged-in users answers complete strangers "
     "too — no login needed. Anything it returns is effectively public."),
    (("403 forbidden bypass", "forbidden bypass"),
     "This page says 'forbidden' to a normal visit, but a small "
     "trick — a changed address spelling or a special header — makes "
     "the server hand over the page anyway. The lock only works from "
     "one direction, so anyone can read what was meant to be private."),
    (("request smuggling",),
     "Two servers in a chain disagree about where one request ends and "
     "the next begins. An attacker can slip a hidden request into that "
     "gap and poison what other visitors receive."),
    (("websocket",),
     "The live connection channel (WebSocket) accepts connections it "
     "should refuse. An attacker can connect through a victim's browser, "
     "or without logging in, and read or send data."),
    (("subdomain takeover",),
     "A web address points at a service the owner no longer controls. An "
     "attacker can claim that service and put their own pages on the "
     "company's address."),
    (("sql injection",),
     "The website passes what a user types straight into its database. An "
     "attacker can trick the database into showing, changing, or deleting "
     "data it should protect."),
    (("cross-site scripting", "xss"),
     "The website shows user input on a page without cleaning it first. An "
     "attacker can hide harmful code in that input and run it in other "
     "visitors' browsers."),
    (("command injection",),
     "The website passes user input to the computer's command line. An "
     "attacker can add their own commands and take control of the server."),
    (("local file inclusion", "path traversal", "directory traversal"),
     "The website lets users ask for files by name without checking the "
     "request. An attacker can step outside the allowed folder and read "
     "private files on the server."),
    (("server-side request forgery", "ssrf"),
     "The website fetches web addresses that the user provides. An attacker "
     "can make the server visit internal addresses it should never touch, "
     "like cloud admin pages."),
    (("xml external entity", "xxe"),
     "The website reads XML in an unsafe way. A crafted XML file can make "
     "the server read private files or visit internal addresses."),
    (("request forgery", "csrf"),
     "Actions can happen without checking they were really requested by "
     "the logged-in user. A trick page can silently make a victim's "
     "browser perform actions for the attacker."),
    (("idor", "access control", "sequential object"),
     "The website shows data based on an ID number without checking the "
     "visitor owns it. Changing the number can reveal other people's data."),
    (("open redirect",),
     "The website sends visitors to whatever address is passed in a link. "
     "Attackers use this to make phishing links look like they belong to "
     "the real website."),
    (("crlf", "response splitting"),
     "User input can sneak line breaks into the website's replies. This "
     "lets an attacker fake parts of the response, like adding their own "
     "headers or content."),
    (("template injection", "ssti"),
     "User input is placed inside a template that the server processes. An "
     "attacker can add template commands that run on the server."),
    (("prototype pollution",),
     "The app mixes what a user sends into its shared settings without "
     "checking the names. A name like __proto__ reaches the master copy "
     "every object is built from, so one request can quietly change "
     "settings — like prices or admin flags — for everyone using the app."),
    (("deserialization", "insecure deserialization"),
     "The app rebuilds objects from text a user sends, without checking "
     "it first. A crafted object can make the server run the attacker's "
     "code or hand over its secrets, because rebuilding is treated as "
     "safe when it isn't."),
    (("remote file inclusion",),
     "The website loads files from addresses the user provides. An "
     "attacker can make it load their own harmful file and run it."),
    (("nosql",),
     "User input goes into a NoSQL database query without cleaning. An "
     "attacker can change the query's meaning, for example to log in "
     "without a password."),
    (("ldap",),
     "User input goes straight into the directory (login) service query. "
     "An attacker can change the query to bypass login or find other "
     "users."),
    (("jwt", "json web token"),
     "The site uses a token (JWT) to prove who is logged in, and the token "
     "is weak or not checked properly. An attacker can forge tokens and "
     "pretend to be another user, even an admin."),
    (("default credential",),
     "The login accepts a well-known default username and password, like "
     "admin/admin. Anyone on the internet can try these and get in."),
    (("api specification", "openapi", "swagger"),
     "The site's full API map is public. It shows attackers every endpoint "
     "and exactly how to use it."),
    (("sensitive file", ".env", "discovered content", "backup file"),
     "A private file is reachable from the internet. Files like this often "
     "contain passwords, keys, or settings that help an attacker get "
     "further in."),
    (("directory listing",),
     "The server shows a list of all files in a folder to any visitor. "
     "Attackers use these lists to find backups, code, and other files "
     "worth stealing."),
    (("security header", "clickjacking", "x-frame"),
     "A protective browser setting is missing. This makes attacks like "
     "clickjacking and script injection easier against visitors."),
    (("cookie",),
     "A login cookie is missing safety flags. That makes it easier to "
     "steal the cookie or send it over an unsafe connection."),
    (("cors", "cross-origin"),
     "The website lets other sites read its responses too freely. A "
     "malicious page could read a logged-in user's data from their "
     "browser."),
    (("cache poisoning", "host header"),
     "The website trusts input that attackers control, and the result can "
     "be stored for other visitors. This can send many users to an "
     "attacker's site."),
    (("spf",),
     "The domain's email sender rules (SPF) are weak or broken. Attackers "
     "can more easily send fake emails that look like they come from this "
     "domain."),
    (("dmarc",),
     "The domain's email protection policy (DMARC) is weak or missing. "
     "Fake emails pretending to be from this domain are less likely to be "
     "blocked."),
    (("dkim",),
     "Email signing (DKIM) for this domain has a problem. It weakens the "
     "proof that emails really came from this domain."),
    (("dnssec",),
     "DNS answers for this domain are not signed (no DNSSEC). Attackers "
     "who can tamper with DNS can redirect visitors to fake servers."),
    (("certificate", "tls", "ssl", "cipher"),
     "The encrypted connection (HTTPS) is weak, old, or has a certificate "
     "problem. Attackers on the network may be able to read or alter the "
     "traffic."),
    (("https redirect", "transport security", "mixed content"),
     "The site does not fully force the secure HTTPS version. Data sent "
     "over plain HTTP can be read or changed on the network."),
    (("email address", "email harvest"),
     "Email addresses are publicly visible. Attackers collect them for "
     "phishing and spam campaigns."),
    (("cloud storage", "bucket", "s3"),
     "A cloud storage location is open to the public. Anyone may be able "
     "to list or read the files inside."),
    (("open port", "exposed service", "port scan"),
     "A service is reachable from the internet that usually should not be. "
     "Each open service is another door an attacker can try."),
    (("vulnerable", "cve-", "outdated"),
     "The software shows a version with known security holes. Attackers "
     "can look up ready-made attacks for that exact version."),
    (("stack trace", "error message", "debug"),
     "The website shows detailed internal error messages. These reveal how "
     "the system is built and help attackers plan their next step."),
    (("source map", "secret", "api key", "source code"),
     "Material meant only for the server (keys, code details, or settings) "
     "is visible to visitors. Attackers can use it to get deeper access."),
    (("excessive data",),
     "The website sends back more personal data than the page needs. "
     "Anyone who can call that endpoint can collect the extra data."),
    (("rate limit",),
     "The website does not slow down repeated attempts. Attackers can "
     "guess passwords or codes as fast as they like."),
    (("race condition", "inconsistent responses"),
     "Doing the same action many times at once gives different results. "
     "This can let attackers bypass limits, like using something twice "
     "that should work only once."),
    (("session",),
     "Login sessions are not handled safely. An attacker may be able to "
     "reuse or fix a session ID and ride on someone else's login."),
    (("graphql",),
     "The GraphQL API gives away its full structure or accepts unsafe "
     "queries. Attackers get a map of the data and new ways to pull it "
     "out."),
    (("upload",),
     "The website accepts uploaded files without checking them properly. "
     "An attacker may upload a harmful file and get it to run on the "
     "server."),
    (("http method",),
     "The server allows risky HTTP methods (like PUT or DELETE). If they "
     "are not locked down, attackers may change or delete files."),
    (("robots.txt",),
     "The robots.txt file lists pages the site wants hidden from search "
     "engines. That list also points attackers straight at private "
     "areas."),
    (("development host", "dev host", "staging"),
     "A test or development version of the site is reachable from the "
     "internet. These copies are often less protected than the live "
     "site."),
    (("waf",),
     "A web application firewall (WAF) sits in front of the site. This is "
     "information for the report; it also means some attacks were "
     "blocked, so coverage may be limited."),
    (("technolog", "fingerprint", "banner", "server header"),
     "The site reveals what software it runs. This is not a hole by "
     "itself, but it tells attackers exactly what to target."),
    (("custom rule",),
     "A custom detection rule you defined matched this page. Check the "
     "details to see what was found."),
]

_FALLBACK = ("A security weakness was found here. The details below "
             "explain what is wrong, the proof shows the evidence, and "
             "the fix section says how to repair it.")


def explain(title):
    """1-2 simple lines explaining a finding type, in plain words."""
    t = (title or "").lower()
    for keys, text in _RULES:
        if any(k in t for k in keys):
            return text
    return _FALLBACK
