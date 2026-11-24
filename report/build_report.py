import pathlib
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                                Image, Preformatted, PageBreak, KeepTogether)

root = pathlib.Path(__file__).resolve().parent.parent
shots = root / "screenshots"
ss = getSampleStyleSheet()
B = ParagraphStyle("B", parent=ss["BodyText"], fontName="Helvetica", fontSize=10.2, leading=14, spaceAfter=6)
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=15, spaceBefore=10, spaceAfter=6, keepWithNext=1, textColor=colors.HexColor("#1f3a5f"))
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=11.5, spaceBefore=6, spaceAfter=4, textColor=colors.HexColor("#1f3a5f"))
CAP = ParagraphStyle("CAP", parent=B, fontSize=8.5, leading=11, textColor=colors.HexColor("#555555"), alignment=1)
CELL = ParagraphStyle("CELL", parent=B, fontSize=8.8, leading=11.5, spaceAfter=0)
CODE = ParagraphStyle("CODE", fontName="Courier", fontSize=7.8, leading=9.6, backColor=colors.HexColor("#f4f4f6"),
                      borderPadding=4, spaceAfter=8)

def P(t): return Paragraph(t, B)
def bullets(items): return [Paragraph("&bull; " + i, ParagraphStyle("bl", parent=B, leftIndent=14, firstLineIndent=-8, spaceAfter=3)) for i in items]
def img(name, cap, w=15.5):
    from PIL import Image as PI
    iw, ih = PI.open(shots / name).size
    return KeepTogether([Image(str(shots / name), width=w*cm, height=w*cm*ih/iw), Paragraph(cap, CAP), Spacer(1, 6)])
def table(rows, widths, head=True):
    data = [[Paragraph(str(c), CELL) for c in r] for r in rows]
    t = Table(data, colWidths=[w*cm for w in widths], repeatRows=1)
    st = [("GRID", (0,0), (-1,-1), 0.4, colors.grey), ("VALIGN", (0,0), (-1,-1), "TOP")]
    if head: st += [("BACKGROUND", (0,0), (-1,0), colors.HexColor("#dbe5f1"))]
    t.setStyle(TableStyle(st)); return t

S = []
S += [Paragraph("Symmetric Encryption with AES-256-GCM: Implementation and Security Evaluation",
        ParagraphStyle("T", parent=ss["Title"], fontSize=17, leading=21)),
      Paragraph("Software Security Homework, EU University of Applied Sciences, Winter 2026<br/>"
                "Student: Madhab Acharya &nbsp;|&nbsp; Date: 23 November 2026", ParagraphStyle("sub", parent=B, alignment=1)),
      Spacer(1, 4)]

# ---------------- Task 1
S += [Paragraph("1. Theoretical Understanding", H1), Paragraph("1.1 Symmetric vs. asymmetric encryption", H2),
 P("Symmetric encryption uses the same secret key to encrypt and decrypt, so both sides must share that key in advance. "
   "Asymmetric encryption (RSA, ECC) uses a key pair: a public key that anyone can have, and a private key that stays secret. "
   "Asymmetric methods are much slower, so they are mostly used to exchange keys or sign data. Symmetric ciphers do the bulk "
   "work. Real systems such as TLS use both: an asymmetric step agrees on a symmetric key, and that key protects the data."),
 table([["", "Symmetric (AES)", "Asymmetric (RSA, ECC)"],
        ["Keys", "One shared secret key", "Public and private key pair"],
        ["Speed", "Very fast", "Slow, for small data only"],
        ["Key sharing", "Hard: the secret must be shared safely", "Easy: the public key can be published"]],
       [3.0, 6.5, 6.5]),
 Paragraph("1.2 The AES algorithm", H2),
 P("AES [1] is a block cipher. It encrypts data in fixed <b>128-bit (16-byte) blocks</b> and supports <b>128, 192 or 256-bit keys</b>, "
   "which use 10, 12 and 14 rounds. Each round mixes the block with a round key through substitution, row shifting and column mixing "
   "(the last round skips column mixing). No attack faster than brute force is known against full AES. Because a block cipher "
   "only handles one block, a <i>mode of operation</i> (ECB, CBC, GCM) is needed for longer data, and the mode matters as much as the key size."),
 Paragraph("1.3 Advantage and limitation", H2),
 P("<b>Advantage:</b> speed. AES is hardware accelerated, so encrypting every customer record costs very little. "
   "<b>Limitation:</b> key management. Anyone with the key can read all the data, so the key must be shared, stored and rotated safely.")]

# ---------------- Task 2
S += [Paragraph("2. Practical AES-256-GCM Implementation", H1),
 P("The program <font name='Courier'>code/aes_gcm_demo.py</font> uses the <font name='Courier'>AESGCM</font> class from the "
   "<font name='Courier'>cryptography</font> library [4]. AES is not implemented by hand, and all data is synthetic."),
 *bullets([
  "<b>Key:</b> <font name='Courier'>AESGCM.generate_key(bit_length=256)</font> takes 32 random bytes from the operating system's secure random generator.",
  "<b>Encryption:</b> the record is turned into JSON and encrypted with a fresh random 12-byte nonce. The Customer_ID is passed as associated data, which is authenticated but not encrypted, so the ciphertext cannot be moved to another customer's row.",
  "<b>Output:</b> the nonce, ciphertext and 16-byte authentication tag are printed in hex and Base64.",
  "<b>Decryption:</b> the library checks the tag first and only then returns the plaintext. The result matches the original record.",
  "<b>Exception handling:</b> a failed check (wrong key, wrong associated data, modified data) is caught and reported as one generic error that does not reveal the cause."]),
 img("01_task2_encrypt_decrypt.png", "Figure 1: Output of aes_gcm_demo.py: encryption, successful decryption and handled failures.", 15.0),
 P("<b>How it works.</b> GCM combines counter-mode encryption with an authentication check. The nonce and a counter are encrypted with AES to make a keystream, "
   "which is XORed with the plaintext. A hash over the associated data and ciphertext is then encrypted into the tag. "
   "On decryption the tag is recomputed, and any difference stops the process.")]

# ---------------- Task 3
S += [Paragraph("3. Security Analysis and Experiments", H1),
 Paragraph("3.1 Experiment A: ciphertext modification", H2),
 P("A record was encrypted with AES-GCM and one bit of one ciphertext byte was flipped. Decryption then failed with an <i>InvalidTag</i> error and returned no plaintext (Figure 2). "
   "The tag depends on every ciphertext bit, so any change makes the recomputed tag differ from the stored one, and an attacker without the key cannot compute a valid tag. "
   "This protects integrity: changed, cut or swapped data is detected before the application uses it. "
   "As a control, the same flip in plain CTR mode (no tag) changed the balance from 15000 to 95000 without any error, so encryption alone does not protect integrity."),
 img("02_expA_tampering.png", "Figure 2: The modified ciphertext, tag and nonce are rejected; the unauthenticated control accepts a silent change.", 15.0),
 Paragraph("3.2 Experiment B: AES operating modes", H2),
 table([["", "AES-ECB", "AES-CBC", "AES-GCM"],
        ["Confidentiality", "Weak: equal plaintext blocks give equal ciphertext blocks", "Good with a random IV", "Strong"],
        ["Integrity", "None: blocks can be swapped or copied unnoticed", "None: bit flips change the plaintext in a predictable way", "Built-in tag detects changes"],
        ["Implementation risks", "Unsafe by design", "Needs padding, a random IV and a separate MAC", "Reusing a nonce with the same key leaks data and breaks authentication [2]"]],
       [2.8, 4.4, 4.4, 4.4]),
 Spacer(1, 4),
 P("<b>Why ECB is unsuitable for customer records.</b> Records have a fixed layout, and values such as currency or status repeat across many rows. "
   "ECB encrypts each 16-byte block on its own, so equal values give equal ciphertext blocks. In the experiment (Figure 3), two records shared the name block and all three shared the currency block. "
   "An observer learns which customers share attributes, and with no authentication can copy blocks between rows."),
 img("03_expB_modes.png", "Figure 3: ECB repeats equal blocks and allows block swapping; CBC accepts bit flips; GCM nonce reuse leaks the XOR of plaintexts.", 14.0),
 Paragraph("3.3 Experiment C: key management", H2),
 P("<b>Risks of keys in source code.</b> The key is copied into every clone, backup and build, and stays in version history even after deletion. "
   "Anyone who can read the code can decrypt all data. One leak exposes every customer, and changing the key means rebuilding and redeploying, "
   "so it rarely happens. Access to the key also cannot be audited or revoked."),
 P("<b>Secure approach (envelope encryption, following [3]).</b> Figure 4 shows it in <font name='Courier'>experiments.py C</font>."),
 *bullets([
  "<b>Generate:</b> create keys with a secure random generator inside a key management service (KMS) or HSM, never from passwords or constants.",
  "<b>Store:</b> keep data keys encrypted (wrapped) by a master key that never leaves the KMS. The application gets access at runtime through its IAM role.",
  "<b>Rotate:</b> change keys on a schedule and after any suspected leak. Rotating the master key only re-wraps the small data keys. Each ciphertext stores a key version so old and new keys can coexist."]),
 img("04_expC_key_management.png", "Figure 4: Envelope encryption: a data key wrapped by a master key, with master-key and data-key rotation.", 13.0)]

# ---------------- Task 4
S += [Paragraph("4. Security Recommendations", H1),
 table([["Area", "Recommendation"],
  ["AES mode", "Use <b>AES-256-GCM</b> [2]. It gives confidentiality and integrity together, needs no padding, is fast, and is easy to use safely through the library. "
   "Financial data must stay secret and also be tamper-evident. Avoid ECB, and avoid CBC without a MAC."],
  ["Key storage and access", "Keep master keys in a KMS or HSM and store data keys wrapped. Give each service only the access it needs, require MFA for key admins, log all key use, "
   "and keep keys out of source code, images and logs."],
  ["Nonces", "Generate a new random 96-bit nonce for every encryption and store it with the ciphertext. Never let callers choose nonces. "
   "Rotate the key before about 2<super>32</super> encryptions under one key [2]."],
  ["Additional measure", "Encrypt sensitive fields in the application so database admins and backups only see ciphertext, send data over TLS, and add secret scanning in CI to block committed keys."]],
  [3.4, 12.6]),
 Paragraph("5. Conclusion", H1),
 P("AES-256-GCM from a trusted library protects customer records well, but only when used correctly. In the experiments, "
   "an unauthenticated mode, a reused nonce or a badly stored key each broke the protection even though the encryption still worked. "
   "The company should use AES-GCM with unique nonces and keep its keys in a KMS with regular rotation.")]

refs = [
 "[1] NIST, <i>FIPS 197: Advanced Encryption Standard (AES)</i>, 2001. https://csrc.nist.gov/pubs/fips/197/final",
 "[2] M. Dworkin, <i>NIST SP 800-38D: Galois/Counter Mode (GCM) and GMAC</i>, 2007. https://csrc.nist.gov/pubs/sp/800/38/d/final",
 "[3] E. Barker, <i>NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management</i>, 2020. https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
 "[4] Python Cryptographic Authority, <i>cryptography documentation: AEAD</i>. https://cryptography.io/en/latest/hazmat/primitives/aead/",
]
S += [Paragraph("References", H1)] + [Paragraph(r, ParagraphStyle("r", parent=B, fontSize=9, leading=12, leftIndent=14, firstLineIndent=-14, spaceAfter=3)) for r in refs]
S += [Spacer(1, 4), P("To run the code: <font name='Courier'>pip install cryptography; python aes_gcm_demo.py; python experiments.py</font>.")]

def footer(c, d):
    c.saveState(); c.setFont("Helvetica", 8); c.setFillColor(colors.grey)
    c.drawCentredString(A4[0]/2, 1.2*cm, f"AES Symmetric Encryption | Software Security Homework | page {d.page}"); c.restoreState()

SimpleDocTemplate(str(root / "report" / "report.pdf"), pagesize=A4, leftMargin=2.2*cm, rightMargin=2.2*cm,
                  topMargin=2*cm, bottomMargin=2*cm, title="AES Symmetric Encryption Report").build(S, onFirstPage=footer, onLaterPages=footer)
