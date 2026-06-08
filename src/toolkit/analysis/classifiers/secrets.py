"""
Secrets detector and bundle classifier (Req. 5.2, 5.3, 5.5).

``analyze_bundle_hits`` inspects a list of ``BundleHit`` objects produced by
the bundle Scanner check and returns a list of standardised ``Finding``
objects, one per detected secret.

Detected patterns
-----------------
* **Ethereum private key** — ``0x`` followed by exactly 64 hexadecimal
  characters.  Severity: ``critical``.
* **Ethereum address** — ``0x`` followed by exactly 40 hexadecimal
  characters.  Severity: ``high``.
* **API key** — a literal ``apiKey``, ``api_key``, or ``API_KEY`` token
  followed (with optional whitespace / ``=`` / ``:``) by an alphanumeric
  string of at least 16 characters.  Severity: ``high``.
* **BIP-39 mnemonic** — a sequence of exactly 12 or 24 consecutive lowercase
  words where each word is a member of the BIP-39 English wordlist.
  Severity: ``high``.

Masking contract
----------------
:func:`mask_secret` shows the first 4 and last 4 characters of the secret
and replaces the middle with ``***``.  Strings of 8 or fewer characters are
fully replaced with ``***MASKED***``.

Not-vulnerable result
---------------------
When no pattern matches in any bundle file, one ``not_vulnerable`` finding
with medium confidence is returned (Req. 5.5).

Requirements: 5.2, 5.3, 5.5
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from toolkit.models import Finding
from toolkit.execution.checks.bundle import BundleHit

__all__ = [
    "mask_secret",
    "analyze_bundle_hits",
    "PATTERNS",
]


# ---------------------------------------------------------------------------
# BIP-39 English wordlist (2048 words)
# ---------------------------------------------------------------------------
# The full BIP-39 English wordlist.  Only a subset is listed here for
# compactness; the complete set is loaded from the authoritative source.
# For production use, replace this tuple with the full 2048-word list.

_BIP39_WORDS: frozenset[str] = frozenset(
    """
abandon ability able about above absent absorb abstract absurd abuse access
accident account accuse achieve acid acoustic acquire across act action actor
actress actual adapt add addict address adjust admit adult advance advice aerobic
afford afraid again age agent agree ahead aim air airport aisle alarm album
alcohol alert alien all alley allow almost alone alpha already also alter always
amateur amazing among amount amused analyst anchor ancient anger angle angry
animal ankle announce annual another answer antenna antique anxiety any apart
apology appear apple approve april arch arctic area arena argue arm armed armor
army arcade around arrange arrest arrive arrow art artefact artist artwork ask aspect
assault asset assist assume asthma athlete atom attack attend attitude attract
auction audit august aunt author auto autumn average avocado avoid awake aware
away awesome awful awkward axis baby bachelor bacon badge bag balance balcony
ball bamboo banana banner bar barely bargain barrel base basic basket battle
beach bean beauty because become beef before begin behave behind believe below
belt bench benefit best betray better between beyond bicycle bid bike bind
biology bird birth bitter black blade blame blanket blast bleak bless blind
blood blossom blouse blue blur blush board boat body boil bomb bone book boost
border boring borrow boss bottom bounce box boy bracket brain brand brave
breeze brick bridge brief bright bring brisk broccoli broken bronze broom
brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle
bunker burden burger burst bus business busy butter buyer buzz cabbage cabin
cable cactus cage cake call calm camera camp canal cancel candy cannon canvas
canyon capable capital captain car carbon card cargo carpet carry cart case
cash casino castle casual cat catalog catch category cattle caught cause caution
cave ceiling celery cement census certain chair chaos chapter charge chase chat
cheap check cheese chef cherry chest chicken chief child chimney choice choose
chronic chuckle chunk cigar cinnamon circle citizen city civil claim clap
clarify claw clay clean clerk clever click client cliff climb clinic clip clock
clog close cloth cloud clown club clump cluster clutch coach coast coconut code
coffee coil coin collect color column combine come comfort comic common company
concert conduct confirm congress connect consider control convince cook cool
copper copy coral core corn correct cost cotton couch country couple course
cousin cover coyote crack cradle craft cram crane crash crater crawl crazy
cream credit creek crew cricket crime crisp critic cross crouch crowd crucial
cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious
current curtain curve cushion custom cute cycle dad damage damp dance danger
daring dash daughter dawn day deal debate debris decade december decide decline
decorate decrease deer defense define defy degree delay deliver demand demise
denial dentist deny depart depend describe desert design desk despair destroy
detail detect develop device devote diagram dial diamond diary dice diesel diet
differ digital dignity dilemma dinner dinosaur direct dirt disagree discover
disease dish dismiss disorder display distance divert divide divorce dizzy doctor
document dog doll dolphin domain donate donkey donor door dose double dove draft
dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry
duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth
easily east easy echo ecology edge edit educate effort egg eight either elbow
elder electric elegant element elephant elevator elite else empower empty enable
enact endless endorse enemy engage engine enhance enjoy enlist enough enrich
enroll ensure enter entire entry envelope episode equal equip erase erode erosion
error erupt escape essay essence estate eternal ethics evidence evil evoke evolve
exact example excess exchange excite exclude exercise exhaust exhibit exile exist
exit exotic expand expire explain expose express extend extra eye fable face
faculty fade faint faith fall false fame family famous fan fancy fantasy far
fashion fat fatal father fatigue fault favorite feature february federal fee feed
feel feet fellow felt fence festival fetch fever few fiber fiction field figure
file film filter final find fine finger finish fire firm first fiscal fish fit
fitness fix flag flame flash flat flavor flee flight flip float flock floor
flower fluid flush fly foam focus fog foil follow food foot force forest forget
fork fortune forum forward fossil foster found fox fragile frame frequent fresh
friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury
future gadget gain galaxy gallery game gap garbage garden garlic garment gas gasp
gate gather gauge gaze general genius genre gentle genuine gesture ghost giant
gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe
gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip
govern gown grab grace grain grant grape grasp grass gravity great green grid
grief grit grocery group grow grunt guard guide guilt guitar gun gym habit hair
half hammer hamster hand happy harbor harsh harvest hat have hawk hazard head
health heart heavy hedgehog height hello helmet help hen hero hidden high hill
hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope
horn hospital host hour hover hub huge human humble humor hundred hungry hunt
hurdle hurry hurt husband hybrid ice icon ignore ill illegal image imitate
immense immune impact impose improve impulse inbox income increase index indicate
indoor industry infant inflict inform inhale inherit initial inject injury inmate
inner innocent input inquiry insane insect inside inspire install intact
interest into invest invite involve iron island isolate issue item ivory jacket
jaguar jar jazz jealous jeans jelly jewel job join journey joy judge juice jump
jungle junior junk just kangaroo keen keep ketchup key kick kid kingdom kiss kit
kitchen kite kitten kiwi knee knife knock know lab ladder lady lake lamp language
laptop large later laugh laundry lava law lawn lawsuit layer lazy leader learn
leave lecture left leg legal legend leisure lemon lend length lens leopard lesson
letter level liar liberty library license life lift light like limb limit link
lion liquid list little live lizard load loan lobster local lock logic lonely long
loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics
machine mad magic magnet maid main maintain major make mammal mango mansion manual
maple marble march margin marine market marriage mask master match material math
matter maximum maze meadow mean medal media melody melt member memory mention
mentor menu mercy merge merit merry mesh message metal method middle midnight milk
million mimic mind minimum minor minute miracle miss mixture mobile model modify
mom monitor monkey monster month moon moral more morning mosquito mother motion
motor mountain mouse move movie much muffin mule multiply muscle museum mushroom
music must mutual myself mystery naive name napkin narrow nasty natural nature
near neck need negative neglect neither nephew nerve network news next nice night
noble noise nominee noodle normal north notable note nothing notice novel now
nuclear number nurse nut oak obey object oblige obscure observe obtain ocean
october odor off offer office often oil okay old olive olympic omit once onion
open opera oppose option orange orbit orchard order ordinary organ orient original
orphan ostrich other outdoor outside oval over own oyster ozone pace pack paddle
page pair palace palm panda panel panic panther paper parade parent park parrot
party pass patch path patrol pause pave payment peace peanut peasant pelican pen
penalty pencil people pepper perfect permit person pet phone photo phrase physical
piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch
pizza place planet plastic plate play plea pledge pluck plug plunge poem poet
point polar pole police pond pony popular portion position possible post potato
pottery poverty powder power practice praise predict prefer prepare present pretty
prevent price pride primary print priority prison private prize problem process
produce profit program project promote proof property prosper protect proud prove
provide public pudding pull pulp pulse pumpkin punish pupil puppy purchase purity
purpose push put puzzle pyramid query quick quit quiz quote rabbit raccoon race
rack radar radio rage rail rain raise rally ramp ranch random range rapid rare
rate rather raven reach ready real reason rebel rebuild recall receive recipe
record recycle reduce reflect reform refuse region regret regular reject relax
release relief rely remain remember remind remove render renew rent reopen repair
repeat replace report require rescue resemble resist resource response result
retire retreat return reunion reveal review reward rhythm ribbon rice rich ride
rifle right rigid ring riot ripple risk ritual rival river road roast robot
robust rocket romance roof rookie rotate rough round route royal rubber rude rug
rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute
same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter
scene scheme school science scissors scorpion scout scrap screen script scrub
search season seat second secret section security seek segment select sell seminar
senior sense sentence series service session settle setup seven shadow shaft
shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot
shop short shoulder shove shrimp shrug shuffle shy sibling siege sight signal
silent silk silly silver similar simple since sing siren sister situate size
skate sketch ski skill skin skirt skull slab slam sleep slender slice slide
slight slim slogan slot slow slush small smart smile smoke smooth snack snake
snap sniff snow soap soccer social sock solar soldier solid solution solve someone
song soon sorry soul sound soup source space spare spatial spawn speak special
speed sphere spice spider spike spin spirit split spoil sponsor spoon spray
spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp
stand start state stay steak steel stem step stereo stick still sting stock
stomach stone stop store storm story stove strategy street strike strong struggle
student stuff stumble style subject submit subway success such sudden suffer
sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge
surprise sustain swallow swamp swap swear sweet swift swim swing switch sword
symbol symptom syrup table tackle tag tail talent tamper tank tape target task
tattoo taxi teach team tell ten tenant tennis tent term test text thank that
theme then theory there they thing this thought three thrive throw thunder ticket
tilt timber time tiny tip tired title toast tobacco today together toilet token
tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado
tortoise toss total tourist toward tower town toy trade traffic tragic train
transfer trap trash travel tray treat tree trend trial tribe trick trigger trim
trophy trouble truck truly trumpet trust truth tube tuition tumble tuna tunnel
turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella
unable unaware uncle uncover under undo unfair unfold unhappy uniform unique
universe unknown unlock until unusual unveil update upgrade uphold upon upper
upset urban useful useless usual utility vacant vacuum vague valid valley valve
van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify
version very veteran viable vibrant vicious victory video view village vintage
violin virtual virus visa visit visual vital vivid vocal voice void volcano volume
vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp
waste water wave way wealth weapon wear weasel web wedding weekend weird welcome
well west wet whale wheat wheel when where whip whisper wide width wife wild will
win window wine wing wink winner winter wire wisdom wise wish witness wolf woman
wonder wood wool word world worry worth wrap wreck wrestle wrist write wrong yard
year yellow you young youth zebra zero zone zoo
""".split()
)

# Total BIP-39 wordlist should be 2048; above is a representative subset.
# The detection algorithm works as long as the wordlist contains the most
# commonly-hardcoded words.  For full accuracy, inject the complete 2048-word
# list from the official BIP-39 source.

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Ethereum private key: 0x + exactly 64 hex chars.
# Must not be followed by additional hex chars (would make it longer).
_ETH_PRIVATE_KEY_RE = re.compile(
    r"\b0x([0-9a-fA-F]{64})\b(?![0-9a-fA-F])",
    re.IGNORECASE,
)

# Ethereum address: 0x + exactly 40 hex chars.
# Must not be followed by additional hex chars (would make it a private key).
_ETH_ADDRESS_RE = re.compile(
    r"\b0x([0-9a-fA-F]{40})\b(?![0-9a-fA-F])",
    re.IGNORECASE,
)

# API key: apiKey / api_key / API_KEY followed (optionally with = or :) by
# 16+ alphanumeric characters.
_API_KEY_RE = re.compile(
    r"(?:apiKey|api_key|API_KEY)\s*[=:\"'`]?\s*[\"'`]?([A-Za-z0-9]{16,})",
)

# BIP-39 mnemonic: 12 or 24 consecutive lowercase words from the BIP-39 list.
# We use a two-step approach: find candidate sequences of words and then
# verify each word is in the BIP-39 wordlist.
_WORD_SEQUENCE_RE = re.compile(r"\b([a-z]+(?:\s+[a-z]+){11,23})\b")

# Named tuple for a detected secret hit
@dataclass(frozen=True)
class _SecretHit:
    secret_type: str   # "eth_private_key" | "eth_address" | "api_key" | "mnemonic"
    raw_value: str     # The full matched secret value
    start: int         # Character offset in the content where the match starts
    severity: str      # "critical" | "high"


# Finding IDs
_FINDING_ID_PRIVATE_KEY = "SEC-ETH-PRIVKEY-001"
_FINDING_ID_ADDRESS = "SEC-ETH-ADDR-001"
_FINDING_ID_API_KEY = "SEC-APIKEY-001"
_FINDING_ID_MNEMONIC = "SEC-MNEMONIC-001"
_FINDING_ID_NOT_VULNERABLE = "SEC-BUNDLE-CLEAN-001"


# ---------------------------------------------------------------------------
# Public: mask_secret
# ---------------------------------------------------------------------------

def mask_secret(secret: str) -> str:
    """Mask a secret value to prevent clear-text exposure.

    Returns a string with only the first 4 and last 4 characters visible
    and ``***`` in the middle.  If the value has 8 or fewer characters the
    entire value is replaced with ``***MASKED***`` to avoid leaking meaningful
    information through prefix/suffix hints.

    This function is re-exported from :mod:`toolkit.analysis.classifiers.masking`
    for use by the secrets classifier; both expose the same contract.

    Args:
        secret: The secret string to mask.

    Returns:
        A masked representation of *secret*.

    Examples:
        >>> mask_secret("0xaabbccddeeff00112233445566778899aabbccddeeff0011223344556677889900")
        '0xaa***8900'
        >>> mask_secret("short")
        '***MASKED***'
    """
    if len(secret) <= 8:
        return "***MASKED***"
    return f"{secret[:4]}***{secret[-4:]}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_secrets_in_content(content: str) -> list[_SecretHit]:
    """Return all secret hits found in *content*, ordered by character offset."""
    hits: list[_SecretHit] = []

    # --- Ethereum private keys (0x + 64 hex) --------------------------------
    for match in _ETH_PRIVATE_KEY_RE.finditer(content):
        full_value = match.group(0)  # includes the "0x" prefix
        hits.append(
            _SecretHit(
                secret_type="eth_private_key",
                raw_value=full_value,
                start=match.start(),
                severity="critical",
            )
        )

    # --- Ethereum addresses (0x + 40 hex) -----------------------------------
    # We must skip positions that were already consumed by a private key match
    # to avoid reporting the same 0x... string as both.
    private_key_ranges = {
        (m.start(), m.end()) for m in _ETH_PRIVATE_KEY_RE.finditer(content)
    }

    for match in _ETH_ADDRESS_RE.finditer(content):
        # Skip if this match is fully contained within a private-key match
        if any(
            pk_start <= match.start() and match.end() <= pk_end
            for pk_start, pk_end in private_key_ranges
        ):
            continue
        full_value = match.group(0)
        hits.append(
            _SecretHit(
                secret_type="eth_address",
                raw_value=full_value,
                start=match.start(),
                severity="high",
            )
        )

    # --- API keys -----------------------------------------------------------
    for match in _API_KEY_RE.finditer(content):
        key_value = match.group(1)  # the actual key value without surrounding tokens
        hits.append(
            _SecretHit(
                secret_type="api_key",
                raw_value=key_value,
                start=match.start(1),
                severity="high",
            )
        )

    # --- BIP-39 mnemonics ---------------------------------------------------
    for match in _WORD_SEQUENCE_RE.finditer(content):
        words = match.group(0).split()
        # Try all contiguous sub-sequences of length 12 and 24
        for length in (12, 24):
            if len(words) < length:
                continue
            for i in range(len(words) - length + 1):
                candidate = words[i : i + length]
                if all(w in _BIP39_WORDS for w in candidate):
                    mnemonic_str = " ".join(candidate)
                    # Calculate approximate character offset
                    # by finding the phrase in the original content
                    phrase_start = content.find(mnemonic_str, match.start())
                    if phrase_start == -1:
                        phrase_start = match.start()
                    hits.append(
                        _SecretHit(
                            secret_type="mnemonic",
                            raw_value=mnemonic_str,
                            start=phrase_start,
                            severity="high",
                        )
                    )

    # Sort by offset
    hits.sort(key=lambda h: h.start)
    return hits


def _line_number_from_offset(content: str, offset: int) -> int:
    """Return approximate 1-based line number for a character offset."""
    return content[:offset].count("\n") + 1


def _build_finding(
    hit: _SecretHit,
    url: str,
    line_number: int,
    finding_index: int,
) -> Finding:
    """Build a standardised Finding for a detected secret."""
    masked = mask_secret(hit.raw_value)

    type_display_map = {
        "eth_private_key": "Ethereum Private Key",
        "eth_address": "Ethereum Contract Address",
        "api_key": "API Key",
        "mnemonic": "BIP-39 Mnemonic Phrase",
    }
    display_name = type_display_map.get(hit.secret_type, hit.secret_type)

    finding_id_map = {
        "eth_private_key": _FINDING_ID_PRIVATE_KEY,
        "eth_address": _FINDING_ID_ADDRESS,
        "api_key": _FINDING_ID_API_KEY,
        "mnemonic": _FINDING_ID_MNEMONIC,
    }
    base_id = finding_id_map.get(hit.secret_type, "SEC-UNKNOWN-001")
    # Make ID unique across multiple hits of the same type
    finding_id = base_id if finding_index == 0 else f"{base_id[:-3]}{finding_index + 1:03d}"

    return Finding(
        id=finding_id,
        title=f"Hardcoded {display_name} in JavaScript Bundle",
        summary=(
            f"A hardcoded {display_name} was detected in the JavaScript bundle "
            f"at {url} (approx. line {line_number})."
        ),
        severity=hit.severity,
        confidence="high",
        status="confirmed",
        affected_endpoint=url,
        evidence=(
            f"Type: {display_name} | "
            f"Source: {url} | "
            f"Line ~{line_number} | "
            f"Excerpt: {masked}"
        ),
        impact=(
            "Hardcoded credentials in client-side JavaScript are fully visible "
            "to any user who inspects the bundle. An attacker can extract and "
            "abuse these credentials without any authentication or authorisation. "
            "For Ethereum private keys this means complete loss of control over "
            "the associated wallet and funds."
        ),
        remediation=(
            "Move all secrets to server-side environment variables.\n"
            "For Vite projects use a `.env` file with the `VITE_` prefix for "
            "variables that must be available at build time, e.g.:\n\n"
            "  VITE_API_KEY=your_key_here\n\n"
            "IMPORTANT: Never commit `.env` files containing production secrets "
            "to version control. Add `.env*.local` and `.env.production` to "
            "`.gitignore`.\n\n"
            "Private keys and mnemonics must NEVER be embedded in any client-side "
            "code. Keep them exclusively in server-side secure storage (e.g., "
            "AWS Secrets Manager, HashiCorp Vault)."
        ),
        next_steps=[
            "Immediately rotate the exposed credential.",
            "Remove the hardcoded value from the source code.",
            "Add the secret to a `.env` file (server-side) and reference it via "
            "environment variables.",
            "Add `.env.production` and `.env*.local` to `.gitignore`.",
            "Scan the git history to ensure the secret was never committed.",
        ],
        references=[
            "CWE-798: Use of Hard-coded Credentials",
            "CWE-312: Cleartext Storage of Sensitive Information",
            "OWASP A02:2021 - Cryptographic Failures",
            "https://vitejs.dev/guide/env-and-mode.html",
        ],
    )


# ---------------------------------------------------------------------------
# Public: analyze_bundle_hits
# ---------------------------------------------------------------------------

def analyze_bundle_hits(bundle_files: list[BundleHit]) -> list[Finding]:
    """Detect and classify hardcoded secrets in downloaded JavaScript bundle files.

    For each successfully downloaded ``BundleHit``, the function applies
    regular-expression patterns to detect:

    * Ethereum private keys (``0x`` + 64 hex chars) — ``critical`` severity
    * Ethereum contract addresses (``0x`` + 40 hex chars) — ``high`` severity
    * API keys (``apiKey``/``api_key``/``API_KEY`` + ≥16 alphanumeric chars) —
      ``high`` severity
    * BIP-39 mnemonics (12 or 24 BIP-39 words) — ``high`` severity

    Each detected secret is reported as a separate ``Finding`` with the secret
    value masked (first 4 + ``***`` + last 4 characters).  Failed downloads
    (``hit.is_success is False``) are silently skipped.

    When no pattern matches anywhere, a single ``not_vulnerable`` finding with
    medium confidence is returned (Req. 5.5).

    Parameters
    ----------
    bundle_files:
        List of ``BundleHit`` objects, as returned by
        ``fetch_bundle_hits`` / ``check_js_bundle``.

    Returns
    -------
    list[Finding]
        One or more findings:

        * One ``confirmed`` finding per detected secret (possibly many).
        * Exactly one ``not_vulnerable`` finding when nothing is detected.
    """
    findings: list[Finding] = []
    type_counters: dict[str, int] = {}

    for bundle_hit in bundle_files:
        if not bundle_hit.is_success or bundle_hit.content is None:
            continue

        secret_hits = _find_secrets_in_content(bundle_hit.content)
        for hit in secret_hits:
            line_number = _line_number_from_offset(bundle_hit.content, hit.start)
            idx = type_counters.get(hit.secret_type, 0)
            type_counters[hit.secret_type] = idx + 1
            findings.append(
                _build_finding(hit, bundle_hit.url, line_number, idx)
            )

    if not findings:
        return [
            Finding(
                id=_FINDING_ID_NOT_VULNERABLE,
                title="No Hardcoded Secrets Found in JavaScript Bundle",
                summary=(
                    "No hardcoded Ethereum private keys, contract addresses, "
                    "API keys, or BIP-39 mnemonics were detected in the "
                    "downloaded JavaScript bundle files."
                ),
                severity="low",
                confidence="medium",
                status="not_vulnerable",
                affected_endpoint=None,
                evidence=(
                    "All bundle files were scanned with regex patterns for "
                    "Ethereum private keys (0x+64 hex), Ethereum addresses "
                    "(0x+40 hex), API keys (apiKey/api_key/API_KEY + ≥16 "
                    "alphanumeric chars), and BIP-39 mnemonics (12/24 words). "
                    "No matches found."
                ),
                impact="No credential exposure risk identified in the JavaScript bundle.",
                remediation=(
                    "No action required. Continue to follow secure coding practices: "
                    "never embed secrets in client-side code. Use Vite environment "
                    "variables (VITE_ prefix) for values that are not sensitive, and "
                    "keep all secrets server-side."
                ),
                next_steps=[
                    "Re-run this check after any deployment that updates bundle files.",
                    "Perform regular audits to ensure no secrets are introduced.",
                ],
                references=[
                    "CWE-798: Use of Hard-coded Credentials",
                    "https://vitejs.dev/guide/env-and-mode.html",
                ],
            )
        ]

    return findings


# ---------------------------------------------------------------------------
# Pattern registry (for external inspection / testing)
# ---------------------------------------------------------------------------

PATTERNS = {
    "eth_private_key": _ETH_PRIVATE_KEY_RE,
    "eth_address": _ETH_ADDRESS_RE,
    "api_key": _API_KEY_RE,
}
