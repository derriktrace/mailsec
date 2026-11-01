"""Synthetic examples, never represented as a measured real-mail benchmark."""
from email.message import EmailMessage

CASES = [
    ("receipt", "Orders <orders@northwind.example>", "Your order has shipped",
     "Your order #1842 has shipped. This is a receipt for an already completed purchase. No action is required. Thank you.", "clean"),
    ("marketing", "Promotions <offers@paper-supply.example>", "Office supplies: this week's bulk offer",
     "We sell office paper and stationery. This unsolicited promotional offer gives 10% off bulk orders. Reply unsubscribe to stop these advertisements.", "spam"),
    ("unknown-login", "Account team <account@unfamiliar-service.example>", "Please review your account",
     "Please sign in at https://unfamiliar-service.example/login to review your account. There is no supplied account relationship or information about who initiated this request.", "suspicious"),
    ("mfa-theft", "Microsoft Support <support@microsoft-secure-login.example>", "Urgent: verify your MFA code",
     "This is Microsoft account security. Reply to this email with your password and the six-digit MFA code you just received, or your account will be disabled in 15 minutes. Keep this verification confidential.", "phishing"),
    ("legitimate-code", "Security <security@northwind.example>", "Your requested verification code",
     "Your one-time code is 827491. You requested this code in the Northwind application. Enter it only in the app you already opened. Never share this code with anyone. If you did not request it, ignore this message. No reply is needed.", "clean"),
    ("banking-change", "Acme Plumbing <billing@acme-plurnbing.example>", "Updated banking details for your invoice",
     "I am the billing manager of Acme Plumbing. Urgently send today's invoice payment to our new bank account instead of the usual account. Do not call your normal contact to verify; I am traveling and the transfer must happen now.", "phishing"),
]


def samples():
    for index, (name, sender, subject, text, _) in enumerate(CASES):
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = sender, "analyst@example.org", subject
        msg["Date"] = f"Mon, 28 Sep 2026 10:{index:02d}:00 +0000"
        msg["Message-ID"] = f"<synthetic-{name}@mailsec.example>"
        msg["X-Mailsec-Synthetic"] = "true"
        msg.set_content(text)
        yield name, msg.as_bytes()
