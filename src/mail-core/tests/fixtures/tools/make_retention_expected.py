import ast, json, re, ipaddress, sys
from email.headerregistry import HeaderRegistry
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from orig import parsing
B = sys.argv[2]  # original-project/20261011-thunderbird/backend
from email.message import Message
ns = {"Message": Message, "re": re, "ipaddress": ipaddress, "HeaderRegistry": HeaderRegistry, "parsing": parsing}
def grab(path, names):
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    for node in tree.body:
        n = getattr(node, "name", None) or (node.targets[0].id if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) else None)
        if n in names:
            exec(ast.get_source_segment(src, node), ns)
grab(B + "/app/mail/schemas.py", {"header_safe", "recipient_address"})
rsrc = open(B + "/app/mail/retention.py", encoding="utf-8").read().replace("from .schemas import recipient_address", "")
tree = ast.parse(rsrc)
for node in tree.body:
    n = getattr(node, "name", None) or (node.targets[0].id if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) else None)
    if n in {"normalize_sender_address", "sender_address", "_VERIFICATION", "_TRANSACTIONAL", "_MARKETING", "_UPDATES", "classify_headers", "normalize_uid_validity"}:
        exec(ast.get_source_segment(rsrc, node).replace("        \n", ""), ns)
values = [
 " Person <PERSON@EXAMPLE.COM> ", "Person <person@b\u00fccher.example>", '"support@bank.example" <forged@evil.example>',
 "person@example.com, second@example.com", "nobody", "person@@example.com", "Group: person@example.com;", "Person <person@example.com",
 "John Q. Public <john@example.com>", "<person@example.com>", "person@example.com (Person)", "person @ example.com",
 '"john doe"@example.com', '"john"@example.com', "user@[192.168.0.1]", "user@[IPv6:::1]", "user@[300.1.1.1]",
 "user@example..com", "user@.example.com", "user@example.com.", "user@exa_mple.com", "p\u00e9rson@example.com",
 "=?utf-8?q?J=C3=B6rg?= <joerg@example.com>", "=?utf-8?q?bad=01name?= <x@example.com>", "", "<>", "a@b",
 "user@-example.com", "user@" + "a"*64 + ".com", "x <user@EXAMPLE.com> (c)", "user@xn--bcher-kva.example",
 "user@B\u00dcCHER.example", "Stra\u00dfe <user@stra\u00dfe.de>", "user.name+tag@example.com", "user..name@example.com",
 ".user@example.com", "user@example.com,", "user@example.com;", "a\b@example.com", '"a,b"@example.com', '"a b" <c@d.e>',
 "user@ex ample.com", "<user@example.com> trailing", "user@example.com <x@y.z>", "@example.com", "user@", "user@\u3002example.com",
]
out = []
for v in values:
    try:
        out.append([v, ns["normalize_sender_address"](v), None])
    except ValueError as e:
        out.append([v, None, str(e)])
raws = [
 b"From: Person <PERSON@example.com>\r\n\r\n",
 b"From: person@example.com\r\nFrom: second@example.com\r\n\r\n",
 b"Subject: x\r\n\r\n",
 b"From: Person\r\n <person@example.com>\r\n\r\n",
 "From: J\u00f6rg <joerg@b\u00fccher.example>\r\n\r\n".encode(),
 b"From: Bad \xff <x@example.com>\r\n\r\n",
 b"From: =?utf-8?q?J=C3=B6rg?= <joerg@example.com>\r\n\r\n",
]
senders = [[r.decode("latin-1"), ns["sender_address"](parsing.parse_message(r))] for r in raws]
subjects = ["Your verification code", "Reset your password", "Invoice #123", "Your order confirmation", "Exclusive offer: 20% off",
 "Weekly newsletter", "Product update", "New comment on your post", "Can you review this code?", "Please order the tasks", "Hello",
 "OTP: 1234", "Sign-in code", "signin code", "sale!", "Wholesale prices", "50% OFF today", "save 10%", "Security alert",
 "Privacy policy update", "=?utf-8?q?Verify_your_email?=", "VERIFICATION", "promotional", "promo", "Payment failed", "Refund issued",
 "Booking confirmation", "notifications", "\u00e9sale", "sale\u00e9"]
classify = []
for s in subjects:
    for extra in ("", "List-Unsubscribe: <x>\r\nPrecedence: Bulk \r\n", "List-Id: x\r\n"):
        m = parsing.parse_message(f"Subject: {s}\r\n{extra}\r\n".encode())
        classify.append([s, extra, ns["classify_headers"](m)[0]])
uids = []
for u in ["99", " 42 ", "0", "4294967295", "4294967296", "00001", "12345678901", "1 UID 2", "", "+5", "\u0661", "-1", "7\n"]:
    uids.append([u, ns["normalize_uid_validity"](u)])
json.dump({"normalize": out, "senders": senders, "classify": classify, "uid_validity": uids}, open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(len(out), len(senders), len(classify))
