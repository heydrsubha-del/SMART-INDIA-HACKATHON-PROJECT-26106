# Privacy Policy — Algorithmistic

**Last updated:** [DATE]
**Operator:** [Subhajit Sarkar] ("we", "us")
**Contact:** [heydrsubha@gmail.com]
**Service URL:** [YOUR APP URL]
**Source code:** https://github.com/heydrsubha-del/SMART-INDIA-HACKATHON-PROJECT-26106

Algorithmistic is an email threat-analysis tool. It examines email messages you
give it and reports whether they look like phishing or fraud. This policy
explains what data the service handles, why, and what control you have.

---

## 1. What data we handle

**a) Emails you provide.** If you upload `.eml`/`.txt` files or a CSV, or connect a
mailbox, the service reads the message content: headers, sender and recipient
addresses, subject, body text, links, attachments, and the routing
information (including IP addresses) contained in the headers.

**b) Mailbox access (optional).** If you use the live mailbox feature, the
service connects to your mail provider over IMAP in **read-only** mode. It
does not send, delete, move, or mark any message. Depending on how you sign
in, we handle:
- an **app password** you type in, or
- a **Google OAuth access token** obtained when you choose "Sign in with
  Google", together with the email address of the signed-in account.

We never see or collect your Google account password.

**c) Analysis results.** The output of the analysis: risk scores, verdicts,
extracted indicators (URLs, domains, IP addresses, sender addresses, crypto
wallet strings), routing and location estimates, and generated reports.

**d) Your feedback.** If you label a result as correct or incorrect, that label
is stored with the related indicators.

**e) Technical data.** The hosting provider may keep standard server logs
(such as IP address and request time) for security and operations. We do not
add analytics or advertising trackers.

## 2. Why we use it

We use this data only to:
- analyse the messages you submit and show you the results,
- generate the reports you request,
- improve detection accuracy through the stored indicators and feedback
  described in section 5, and
- keep the service secure and working.

We do **not** sell your data, use it for advertising, or use it to build
profiles about you.

## 3. Google user data

If you sign in with Google, the service requests access to your Gmail through
IMAP and to your account email address. This access is used solely to display
and analyse messages inside the app at your request.

The service's use and transfer of information received from Google APIs
adheres to the
[Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy),
including the Limited Use requirements. In particular:
- Google user data is used only to provide the user-facing features you
  see in the app.
- It is not transferred to third parties except as necessary to provide
  those features, to comply with law, or with your consent.
- It is not used for advertising, and it is not sold.
- No humans read your email content, except where you explicitly share a
  report with us, or where required for security or legal reasons.

You can revoke access at any time at
[myaccount.google.com/permissions](https://myaccount.google.com/permissions).

## 4. Third-party services the app contacts

To do its job the service makes limited requests to:

| Service | What is sent | Why |
| --- | --- | --- |
| **ip-api.com** | IP addresses found in email headers | Approximate geolocation and network type |
| **abuse.ch URLhaus** | Nothing about you — we download their public list of malicious URLs | Threat-intelligence sync |
| **Published Tor exit-node list and public VPN range lists** | Nothing about you — we download public lists | Origin classification |
| **Your mail provider (e.g. Google, Yahoo, Microsoft)** | The credentials or token you supply | Read-only mailbox access |
| **Hosting provider** ([YOUR HOST, e.g. Streamlit Community Cloud]) | Everything the app processes, as the server runs there | Running the service |

Optional AI features (threat narratives and semantic correlation) run through
a local Ollama model. [If you have not enabled these on the public service,
say so here; if you have, state where the model runs.]

We do not send email bodies or attachments to any other third-party service.

## 5. What is stored, and for how long

- **Session data.** Uploaded emails, mailbox contents, and tokens are used
  to serve your session. [DESCRIBE: cleared when you close the session /
  stored until deleted — must match the real behaviour of the deployed app.]
- **Threat memory.** The service keeps extracted indicators (such as URLs,
  domains, IP addresses and sender addresses), their scores, and analyst
  feedback in a database so later analyses can reuse them. [DESCRIBE:
  retention period, e.g. deleted after N days.]
- **Sign-in tokens.** [DESCRIBE: tokens are kept only for your session and
  removed when you sign out / expire.] You can also revoke them through
  Google at any time.
- **Reports.** Reports are generated on request and are not kept on the
  server after you download them. [Confirm this matches the deployed app.]

We keep data only as long as needed for the purposes above.

## 6. Sharing

We share data only:
- with the service providers listed in section 4, to the extent needed to
  run the service,
- if the law requires it or a valid legal request is made, or
- with your consent.

## 7. Security

We use HTTPS in transit, keep credentials out of the source code, restrict
mailbox access to read-only, and store tokens with the minimum scope the
feature needs. No system is perfectly secure, so we cannot guarantee
absolute security. If we learn of a breach affecting your data, we will
notify affected users and the relevant authorities as required by law.

## 8. Your choices and rights

You can:
- stop using the service at any time,
- revoke Google access at
  [myaccount.google.com/permissions](https://myaccount.google.com/permissions),
- ask us to delete data associated with you by contacting
  [YOUR CONTACT EMAIL],
- ask what data we hold about you, and ask us to correct it.

If you are in India, you have rights under the Digital Personal Data
Protection Act, 2023, including access, correction, erasure and grievance
redressal. If you are in the EEA or UK, you have similar rights under the
GDPR. To exercise any of them, contact us at the address above.

## 9. Emails contain other people's data

Emails often include personal data about people other than you (senders,
recipients, people mentioned). Only submit messages you are entitled to
analyse. Generated reports contain personal information such as sender
identities and routing details; handle them under your organisation's
data-protection policy and share them only with authorised people.

## 10. Children

The service is not intended for anyone under 18, and we do not knowingly
collect data from children.

## 11. Changes

We may update this policy. The "Last updated" date at the top will change,
and for significant changes we will post a notice in the app or repository.

## 12. Contact

Questions or requests: [heydrsubha@gmail.com]