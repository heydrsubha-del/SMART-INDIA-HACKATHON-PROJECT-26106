"""Builds the labelled training corpus at data/emails.csv.

Public phishing corpora are large and awkward to ship, so we synthesise a
balanced set from templates with randomised slots. It is seeded, so the
dataset - and therefore the trained model - is identical on every machine.

Standalone:  python gen_data.py
"""
import csv
import os
import random

import config as C

SEED = 42

# --- Phishing building blocks ----------------------------------------------
PHISH_BRANDS = ["PayPal", "Microsoft 365", "Apple", "Amazon", "Netflix",
                "HDFC Bank", "SBI NetBanking", "ICICI Bank", "DHL Express",
                "Google Account", "Instagram", "LinkedIn"]
PHISH_HOOKS = [
    "we detected unusual sign-in activity on your account",
    "your account has been temporarily suspended",
    "your payment could not be processed",
    "your password will expire in 24 hours",
    "an unauthorized device accessed your account",
    "your parcel is being held pending a customs fee",
    "your mailbox storage is full and messages are being rejected",
    "your subscription payment was declined",
    "we could not verify your recent transaction",
    "your account will be permanently closed",
]
PHISH_ACTIONS = [
    "click here to verify your identity immediately",
    "confirm your details within 24 hours to avoid suspension",
    "log in now using the secure link below to restore access",
    "update your billing information right away",
    "re-enter your card details to reactivate your account",
    "validate your account using the link below",
    "download the attached form and return it urgently",
]
PHISH_THREATS = [
    "Failure to act will result in permanent account closure.",
    "This is your final notice.",
    "Your account will be locked within 24 hours.",
    "Legal action may follow if this is ignored.",
    "Access will be revoked immediately if unverified.",
    "",
]
PHISH_LINKS = [
    "http://bit.ly/2xKp9Lq", "http://secure-verify-login.tk/account",
    "http://192.168.44.9/login.php", "http://paypa1-support.com/verify",
    "http://tinyurl.com/y8xk2mz", "http://micros0ft-securelogin.ru/auth",
    "http://appleid-verify.support/login", "http://hdfc-netbanking.online/signin",
]
PHISH_SIGNOFF = ["Security Team", "Account Services", "Customer Support",
                 "Billing Department", "IT Helpdesk", "Fraud Prevention Unit"]

# --- BEC (Business Email Compromise) blocks --------------------------------
BEC_TEMPLATES = [
    "Hi, are you at your desk? I need you to process an urgent wire transfer "
    "to a new supplier today. Keep this confidential until it clears. "
    "Send me the confirmation once done. Regards, {name} ({role})",
    "{name} here. I am in a meeting and cannot talk. Please arrange payment of "
    "the attached invoice to the updated bank details below before end of day. "
    "Do not discuss this with anyone else.",
    "Quick favour - I need you to purchase gift cards for a client "
    "appreciation programme. Buy them now and send me the codes. "
    "I will reimburse you. This is time-sensitive. {name}, {role}",
    "Please update the beneficiary bank details for our vendor payment run. "
    "The new IBAN is below. Process the remittance immediately and confirm. "
    "Treat as confidential. {name}",
]
BEC_NAMES = ["Rajesh Kumar", "Anita Sharma", "David Miller", "Priya Nair",
             "Sanjay Mehta", "Karen Fisher"]
BEC_ROLES = ["CEO", "CFO", "Managing Director", "Finance Director"]

# --- Legitimate blocks -----------------------------------------------------
LEGIT_TEMPLATES = [
    "Hi {first}, thanks for your message. I have attached the notes from "
    "yesterday's review meeting. Let me know if anything needs correcting "
    "before I circulate them to the wider team.",
    "Your monthly account statement for {month} is now available. You can view "
    "it any time by signing in to our website directly. No action is needed.",
    "Reminder: the project stand-up moves to 10:30 on Thursday this week "
    "because of the maintenance window. Calendar invites have been updated.",
    "Hello {first}, your order #{num} has shipped and should arrive by {month} "
    "{day}. You can track it from the orders page in your account.",
    "The quarterly engineering newsletter is out. This issue covers the "
    "database migration, our new CI pipeline, and three open positions on the "
    "platform team.",
    "Hi team, please review the attached draft of the design document and add "
    "comments by Friday. I would especially like feedback on the caching "
    "section.",
    "Thank you for attending the workshop on {month} {day}. Slides and the "
    "recording are linked in the shared drive folder we set up for the cohort.",
    "Your support ticket #{num} has been resolved. If the issue reappears, "
    "reply to this email and it will reopen the same ticket for our team.",
    "Hi {first}, I reviewed the pull request and left a few minor comments. "
    "Nothing blocking - happy to approve once the tests pass.",
    "Invitation: the annual all-hands is scheduled for {month} {day} at 15:00 "
    "in the main auditorium. Remote attendees can join via the usual link.",
    "Here is the agenda for next week's sprint planning: carry-over items, "
    "capacity for the release, and a short retrospective on the last cycle.",
    "Your subscription renews on {month} {day}. The receipt will be emailed to "
    "you. You can manage or cancel the plan from your account settings page.",
    "Hi {first}, the library upgrade is merged and deployed to staging. Could "
    "you run through the regression checklist when you get a chance?",
    "Following up on our conversation - I have booked the meeting room for "
    "Tuesday afternoon and invited the vendor's technical contact.",
    "Notice: scheduled maintenance this Saturday from 02:00 to 04:00. Some "
    "services may be briefly unavailable. No customer action is required.",
]
LEGIT_FIRST = ["Priya", "Arjun", "Sam", "Meera", "Tom", "Nisha", "Alex", "Ravi"]
MONTHS = ["January", "March", "April", "June", "July", "September", "November"]
LEGIT_SIGNOFF = ["Best regards", "Thanks", "Kind regards", "Cheers", "Regards"]

# --- HARD NEGATIVES --------------------------------------------------------
# Genuine business mail that legitimately uses the exact vocabulary phishing
# abuses: "invoice", "payment", "verify", "urgent", "account", "expire".
# Without these the classifier just learns "scary word => phishing" and scores a
# fake 100%. These force it to learn CONTEXT, and they are what stops the
# real-world false positives that make security tools get switched off.
LEGIT_HARD = [
    "Hi {first}, invoice #{num} for the Q3 licence renewal is attached. Payment "
    "terms are net 30, so nothing is urgent - our accounts team will process it "
    "through the usual purchase order. Do not send funds to any details other "
    "than those already on file with procurement.",
    "Scheduled notice from IT: your network password will expire in 14 days. "
    "Please change it using Ctrl+Alt+Del on your work machine, or in person at "
    "the service desk. We will never email you a link to reset it, and we will "
    "never ask for your current password.",
    "Your account statement for {month} is ready. To view it, open your banking "
    "app or type our address into your browser yourself. We do not include "
    "sign-in links in statements. No action is needed if the balance looks right.",
    "Security alert from our own IT team: we detected a sign-in to your account "
    "from a new device in the Bengaluru office. If that was you, you can ignore "
    "this message. If not, call the internal helpdesk on extension 4412 - do "
    "not reply to this email with any details.",
    "Hi {first}, following up on the supplier payment we discussed in person "
    "yesterday. I have raised the purchase order through the finance portal as "
    "normal. Please verify the amount matches the signed quotation before "
    "approving it in the system.",
    "Reminder: your subscription renews on {month} {day} and the card on file "
    "will be charged. If you want to cancel, you can do that in account "
    "settings. This is a routine notice and requires no confirmation.",
    "Payroll notice: bank detail changes for this month's run must be submitted "
    "through the HR self-service portal by {month} {day}. Requests sent over "
    "email cannot be actioned - this is deliberate, to prevent payment fraud.",
    "Hi {first}, the auditors have asked us to verify the vendor list before "
    "the year-end close. Could you confirm the contacts for your three "
    "suppliers in the shared sheet? No payment details are needed, just names.",
    "Your parcel #{num} is out for delivery today. The courier will not ask for "
    "any fee on the doorstep, and we will not email you a customs payment link. "
    "You can track progress from the orders page after signing in normally.",
    "Urgent but internal: the staging database is locked and the release is "
    "blocked. {first}, could you look at the migration job when you get a "
    "moment? Nothing customer-facing is affected.",
]

# Phishing without the loud giveaway words - forces the model past keywords.
PHISH_SOFT = [
    "Hello, I hope you are well. Our records show a small discrepancy in your "
    "billing profile from last month. When you have a moment, could you review "
    "the details at {link} and confirm they are correct? Thank you, Accounts.",
    "Good morning, following our note last week regarding your mailbox quota, "
    "the storage upgrade is now available for your account. You can apply it "
    "here: {link}. Regards, IT Services.",
    "Hi, the document you requested from the finance review is ready for you to "
    "look over. It is available at {link}. Please sign in with your work email "
    "to open it. Thanks, Document Services.",
    "Dear colleague, HR has published the revised leave policy for this year. "
    "Acknowledge that you have read it by signing in at {link}. Regards, "
    "People Operations.",
    "Hello, your recent expense claim needs one more approval step before it "
    "can be reimbursed. You can complete it at {link}. Thank you, Expenses "
    "Team.",
]


def _phish_email(rng):
    """One synthetic phishing message. Returns (text, template_id)."""
    brand = rng.choice(PHISH_BRANDS)
    hook_idx = rng.randrange(len(PHISH_HOOKS))
    parts = [
        "{}: {}.".format(brand, PHISH_HOOKS[hook_idx]),
        "Dear Customer, {}.".format(rng.choice(PHISH_ACTIONS)),
        rng.choice(PHISH_LINKS),
        rng.choice(PHISH_THREATS),
        "{}, {}".format(rng.choice(PHISH_SIGNOFF), brand),
    ]
    return " ".join(p for p in parts if p), "phish_loud_{}".format(hook_idx)


def _bec_email(rng):
    """One synthetic business-email-compromise message."""
    idx = rng.randrange(len(BEC_TEMPLATES))
    text = BEC_TEMPLATES[idx].format(name=rng.choice(BEC_NAMES),
                                     role=rng.choice(BEC_ROLES))
    return text, "bec_{}".format(idx)


def _soft_phish_email(rng):
    """Phishing written politely, without the obvious urgency keywords."""
    idx = rng.randrange(len(PHISH_SOFT))
    return (PHISH_SOFT[idx].format(link=rng.choice(PHISH_LINKS)),
            "phish_soft_{}".format(idx))


def _wrap(rng, body, openers):
    """Give a body a realistic greeting and sign-off."""
    return "{} {},\n{}\n{},\n{}".format(
        rng.choice(openers), rng.choice(LEGIT_FIRST), body,
        rng.choice(LEGIT_SIGNOFF), rng.choice(LEGIT_FIRST),
    )


def _fill(rng, template):
    return template.format(
        first=rng.choice(LEGIT_FIRST),
        month=rng.choice(MONTHS),
        day=rng.randint(1, 28),
        num=rng.randint(10000, 99999),
    )


def _hard_legit_email(rng):
    """Legitimate mail that USES phishing vocabulary - the hard negative."""
    idx = rng.randrange(len(LEGIT_HARD))
    body = _fill(rng, LEGIT_HARD[idx])
    return (_wrap(rng, body, ["Hello", "Hi", "Dear"]),
            "legit_hard_{}".format(idx))


def _legit_email(rng):
    """One synthetic legitimate message."""
    idx = rng.randrange(len(LEGIT_TEMPLATES))
    body = _fill(rng, LEGIT_TEMPLATES[idx])
    return (_wrap(rng, body, ["Hello", "Hi", "Good morning"]),
            "legit_plain_{}".format(idx))


def generate(n_per_class=300, path=None):
    """Write the CSV of (text, label, template_id). Returns (path, n_rows).

    Composition per class (deliberate, see LEGIT_HARD):
      phish : 55% loud credential phishing, 25% BEC, 20% soft/polite phishing
      legit : 60% ordinary business mail, 40% HARD NEGATIVES

    template_id records WHICH template produced each row so the classifier can
    hold out entire unseen templates instead of unseen slot-fills. Without that,
    train and test share wording and accuracy is a meaningless 100%.
    """
    path = path or C.EMAILS_CSV
    rng = random.Random(SEED)

    n_bec = int(n_per_class * 0.25)
    n_soft = int(n_per_class * 0.20)
    n_loud = n_per_class - n_bec - n_soft
    n_hard = int(n_per_class * 0.40)
    n_plain = n_per_class - n_hard

    rows = []
    for maker, count, label in (
        (_phish_email, n_loud, "phish"),
        (_bec_email, n_bec, "phish"),
        (_soft_phish_email, n_soft, "phish"),
        (_legit_email, n_plain, "legit"),
        (_hard_legit_email, n_hard, "legit"),
    ):
        for _ in range(count):
            text, template_id = maker(rng)
            rows.append((text, label, template_id))

    rng.shuffle(rows)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["text", "label", "template_id"])
        writer.writerows(rows)
    return path, len(rows)


if __name__ == "__main__":
    p, n = generate()
    templates = set()
    with open(p, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            templates.add(row["template_id"])
    print("wrote {} rows ({} distinct templates) to {}".format(
        n, len(templates), p))
    print("  40% of legit rows are HARD NEGATIVES - genuine mail using phishing")
    print("  vocabulary, so the model must learn context, not keywords.")
