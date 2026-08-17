// Package rules defines the heuristics used to recognise a commit that fixes a
// security bug.
//
// Each rule is a regular expression with a weight, a category, and a scope that
// says what text it is matched against. Weights are additive: a commit's score
// is the sum of the rules that fired, so a rule's weight expresses how much
// evidence one match provides, not how severe the underlying bug is.
package rules

import "regexp"

// Category groups rules by the class of bug they point at.
type Category string

const (
	CatAdvisory    Category = "advisory"
	CatMemory      Category = "memory-safety"
	CatDoS         Category = "dos"
	CatValidation  Category = "input-validation"
	CatCrypto      Category = "crypto"
	CatAuthz       Category = "authz"
	CatConcurrency Category = "concurrency"
	CatInfoLeak    Category = "info-leak"
	CatInjection   Category = "injection"
	CatSupplyChain Category = "supply-chain"
	CatMeta        Category = "meta"
)

// Scope is the text a rule is matched against.
type Scope string

const (
	// ScopeMessage matches the commit subject and body.
	ScopeMessage Scope = "message"
	// ScopeAdded matches lines added by the commit.
	ScopeAdded Scope = "added"
	// ScopeRemoved matches lines removed by the commit.
	ScopeRemoved Scope = "removed"
	// ScopePath matches the paths of the files the commit touched.
	ScopePath Scope = "path"
)

// Rule is a single heuristic.
type Rule struct {
	ID       string
	Scope    Scope
	Category Category
	Weight   int
	Pattern  *regexp.Regexp
	Desc     string
}

// RuleFixShaped is the ID of the rule that recognises a commit phrased as a
// fix. The scanner treats it specially: diff evidence only counts towards a
// finding when the author said they were fixing something.
const RuleFixShaped = "fix-shaped"

func re(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }

// message rules read the commit message, which is the strongest signal
// available: an author fixing a security bug usually says so.
var messageRules = []Rule{
	{
		ID: "advisory-id", Scope: ScopeMessage, Category: CatAdvisory, Weight: 16,
		Pattern: re(`(?i)\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|RUSTSEC-\d{4}-\d{4})\b`),
		Desc:    "references a published advisory",
	},
	{
		ID: "security-advisory", Scope: ScopeMessage, Category: CatAdvisory, Weight: 8,
		Pattern: re(`(?i)\bsecurity advisor(y|ies)\b`),
		Desc:    "calls out a security advisory",
	},
	{
		ID: "security-labeled-update", Scope: ScopeMessage, Category: CatAdvisory, Weight: 14,
		Pattern: re(`(?i)^([^ ]+: )?\[security\] (bump|update|upgrade|patch)\b`),
		Desc:    "security-labelled dependency update",
	},
	{
		ID: "security-explicit", Scope: ScopeMessage, Category: CatAdvisory, Weight: 6,
		Pattern: re(`(?i)\b(security (fix|issue|bug|hole|advisory|patch|vulnerability)|vulnerabilit(y|ies)|exploitab(le|ility)|attack vectors?|threat model violation)\b`),
		Desc:    "calls the change a security fix",
	},
	{
		ID: "external-security-report", Scope: ScopeMessage, Category: CatAdvisory, Weight: 7,
		Pattern: re(`(?i)(\b(hackerone\.com/reports/|bug bounty|security researcher|responsible disclosure)\b|github\.com/[^ ]+/security/(advisories|dependabot)/)`),
		Desc:    "references an external security report",
	},
	{
		ID: "audit", Scope: ScopeMessage, Category: CatAdvisory, Weight: 4,
		Pattern: re(`(?i)\b(audit (finding|issue|report|fix)|pen ?test|responsible disclosure|reported by .{0,40}(security|researcher))\b`),
		Desc:    "originates from an audit or disclosure",
	},

	{
		ID: "memory-overflow", Scope: ScopeMessage, Category: CatMemory, Weight: 6,
		Pattern: re(`(?i)\b((buffer|heap|stack|integer|arithmetic|numeric|u(8|16|32|64|128|size)|i(8|16|32|64|128|size)|counter|length|size|offset|index|duration( value)?|balance|calculation) (over|under)flows?|underflow(s|ed|ing)? (on|when|during|in)|overflow(s|ed|ing)? (on|when|during|in)|wraparound|subtract with overflow|attempt to (add|subtract|multiply) with overflow)\b`),
		Desc:    "arithmetic or buffer overflow",
	},
	{
		ID: "out-of-bounds", Scope: ScopeMessage, Category: CatMemory, Weight: 6,
		Pattern: re(`(?i)\b(out[ -]of[ -]bounds|OOB|index out of (range|bounds)|slice index|range end index|negative index)\b`),
		Desc:    "out-of-bounds access",
	},
	{
		ID: "use-after-free", Scope: ScopeMessage, Category: CatMemory, Weight: 8,
		Pattern: re(`(?i)\b(use[ -]after[ -]free|double free|dangling (pointer|reference)|invalid free|memory corruption)\b`),
		Desc:    "memory corruption",
	},
	{
		ID: "undefined-behaviour", Scope: ScopeMessage, Category: CatMemory, Weight: 7,
		Pattern: re(`(?i)\b(undefined behaviou?r|\bUB\b|unsound(ness)?|miri (failure|error|complain)|aliasing violation|uninitialized (memory|read))\b`),
		Desc:    "unsoundness or undefined behaviour",
	},
	{
		ID: "unsafe-code", Scope: ScopeMessage, Category: CatMemory, Weight: 3,
		Pattern: re(`(?i)\bunsafe\b.{0,40}\b(fix|remove|replace|audit|bug|block)|\b(fix|remove|replace|audit)\w*\b.{0,40}\bunsafe\b`),
		Desc:    "touches unsafe code",
	},

	{
		ID: "panic", Scope: ScopeMessage, Category: CatDoS, Weight: 4,
		Pattern: re(`(?i)\b(panic(s|ked|king)?|unwrap (on|of)|expect\(\)|assertion fail(ure|ed)?|debug_assert)\b`),
		Desc:    "panic or failed assertion",
	},
	{
		ID: "crash", Scope: ScopeMessage, Category: CatDoS, Weight: 5,
		Pattern: re(`(?i)\b(crash(es|ed|ing)?|segfault|SIGSEGV|SIGABRT|abort(s|ed)? the (process|node)|process exit)\b`),
		Desc:    "crash",
	},
	{
		ID: "denial-of-service", Scope: ScopeMessage, Category: CatDoS, Weight: 7,
		Pattern: re(`(?i)\b(denial[ -]of[ -]service|DDoS( (attack|vector|risk))?|DoS (attack|vector|risk|vulnerability|issue|fix)|((fix|prevent|mitigate)(es|ed|ing)? .{0,30}[[:space:]])DoS|griefing|amplification attack|resource exhaustion)\b`),
		Desc:    "denial of service",
	},
	{
		ID: "resource-exhaustion", Scope: ScopeMessage, Category: CatDoS, Weight: 6,
		Pattern: re(`(?i)\b(OOM|out of memory|memory (exhaustion|blowup|spike|leak)|unbounded (growth|allocation|memory|queue|buffer|channel|recursion)|allocat(e|es|ing) .{0,20}(attacker|untrusted|arbitrary)|excessive (memory|allocation)|giant (memory )?allocation)\b`),
		Desc:    "unbounded resource use",
	},
	{
		ID: "hang", Scope: ScopeMessage, Category: CatDoS, Weight: 5,
		Pattern: re(`(?i)\b(infinite (loop|recursion)|loop(s|ed|ing)? forever|stack overflow|hang(s|ing)?|deadlock|livelock|stall(s|ed|ing)?|stuck (on|in|while|waiting)|never (terminates|completes)|busy loop|spinning (forever|indefinitely))\b`),
		Desc:    "hang or non-termination",
	},
	{
		ID: "divide-by-zero", Scope: ScopeMessage, Category: CatDoS, Weight: 5,
		Pattern: re(`(?i)\b(divi(de|sion) by zero|div(ide)?[ _-]?by[ _-]?zero|modulo zero)\b`),
		Desc:    "division by zero",
	},

	{
		ID: "hostile-input", Scope: ScopeMessage, Category: CatValidation, Weight: 6,
		Pattern: re(`(?i)\b(malformed|malicious|adversarial|untrusted|hostile|byzantine|corrupt(ed)?|attacker[ -]controlled) (input|data|message|payload|packet|request|response|block|proof|certificate|signature|header|peer|bytes|value|length|transaction|instruction|account|shred|chunk|frame|archive|source|vote|filter|collector|log|record|object|state|gossip|program)s?\b`),
		Desc:    "handles hostile input",
	},
	{
		ID: "attacker-context", Scope: ScopeMessage, Category: CatValidation, Weight: 5,
		Pattern: re(`(?i)\b(attacker(s|'s)?|attackers'|adversar(y|ies))\b.{0,50}\b(can|could|controlled|submit|send|cause|trigger|craft|exploit)|\bprotect(ion|s|ed|ing)? against (an )?(attacker|attackers|adversary|adversaries)\b`),
		Desc:    "describes attacker-controlled behaviour",
	},
	{
		ID: "missing-validation", Scope: ScopeMessage, Category: CatValidation, Weight: 4,
		Pattern: re(`(?i)\b(bounds[ -]check|length check|missing (check|validation|bound)|validate|validation|sanitiz(e|ing|ation)|reject(s|ed|ing)? (invalid|malformed|oversized|duplicate)|enforce (a )?(limit|bound|max)|verify (the )?(length|size|bounds|input))\b`),
		Desc:    "adds validation",
	},
	{
		ID: "fuzz-crash", Scope: ScopeMessage, Category: CatValidation, Weight: 6,
		Pattern: re(`(?i)\b(fuzz\w*|oss-fuzz|libfuzzer|afl|honggfuzz)\b.{0,40}\b(crash|panic|bug|failure|regression|finding|found|leak|hang|timeout|oom)|\b(crash|panic|bug|failure|regression|finding|found|leak|hang|timeout|oom)\b.{0,40}\bfuzz\w*|\breproducer\b`),
		Desc:    "a fuzzer found the bug",
	},
	{
		ID: "fuzz-mention", Scope: ScopeMessage, Category: CatValidation, Weight: 2,
		Pattern: re(`(?i)\b(fuzz(er|ing|ed)?|oss-fuzz|libfuzzer|honggfuzz)\b`),
		Desc:    "mentions fuzzing",
	},
	{
		ID: "malleability", Scope: ScopeMessage, Category: CatValidation, Weight: 5,
		Pattern: re(`(?i)\b(malleab(le|ility)|non[ -]canonical|canonical(ity|ization)|ambiguous encoding|duplicate (key|entry|element) (accepted|allowed)|second[ -]pre[ -]?image( attacks?)?)\b`),
		Desc:    "encoding malleability",
	},

	{
		ID: "crypto-side-channel", Scope: ScopeMessage, Category: CatCrypto, Weight: 8,
		Pattern: re(`(?i)\b(timing (attack|leak|side[ -]channel|variance)|constant[ -]time|non[ -]constant[ -]time|side[ -]channel|cache attack|branch on secret)\b`),
		Desc:    "side channel",
	},
	{
		ID: "crypto-key-handling", Scope: ScopeMessage, Category: CatCrypto, Weight: 8,
		Pattern: re(`(?i)\b(zeroiz(e|ing|ation)|key material|secret (key|material) (leak|expos)|leak(s|ed|ing)? (the )?(private key|secret|seed|nonce)|weak (rng|randomness|entropy|key)|predictable (nonce|seed|random)|nonce reuse|reus(e|ed|ing) (a )?nonce|small subgroup|invalid curve|point (validation|not validated))\b`),
		Desc:    "key or randomness handling",
	},
	{
		ID: "crypto-verification", Scope: ScopeMessage, Category: CatCrypto, Weight: 8,
		Pattern: re(`(?i)\b(signature|proof|certificate|merkle|commitment|mac|hmac|hash|digest|threshold share)\b.{0,50}\b(forg(e|ed|ery)|bypass|not (verified|checked|validated)|missing (verification|check)|always (true|succeeds)|accepted? without|skipped)`),
		Desc:    "verification gap",
	},
	{
		ID: "crypto-proof-bounds", Scope: ScopeMessage, Category: CatCrypto, Weight: 6,
		Pattern: re(`(?i)\b(0[ -]bit range proof|zero[ -]bit range proof|range proof (generator )?(length|size|bound)|proof generator (length|size|bound))\b`),
		Desc:    "bounds cryptographic proof generation or verification",
	},

	{
		ID: "authz", Scope: ScopeMessage, Category: CatAuthz, Weight: 8,
		Pattern: re(`(?i)\b(auth(entication|orization)? bypass|access control|privilege escalation|permission check|unauthoriz(ed|ation)|impersonat(e|ion)|spoof(ing|ed)?)\b`),
		Desc:    "access control",
	},
	{
		ID: "privilege-validation", Scope: ScopeMessage, Category: CatAuthz, Weight: 8,
		Pattern: re(`(?i)\b(missing|omit(ted)?|bypass(ed|es|ing)?|fail(s|ed)? to (check|verify|validate)) (the )?(owner(ship)?|signer|signature|writable|authority|permission|privilege)( (check|validation|verification))?\b|\b(owner(ship)?|signer|signature|writable|authority|permission|privilege) (check|validation|verification) (is |was )?(missing|omitted|bypassed)|\bnot signed by (the )?authority\b|\b(writable|signer) privilege(s)?\b`),
		Desc:    "missing ownership, signer, or privilege validation",
	},
	{
		ID: "consensus-safety", Scope: ScopeMessage, Category: CatAuthz, Weight: 6,
		Pattern: re(`(?i)\b(replay (attack|protection)|equivocat(e|ion|ing)|double[ -](spend|sign|vote|propose)|safety violation|liveness (bug|violation|failure)|fork(ing)? (attack|the chain)|eclipse attacks?|sybil)\b`),
		Desc:    "protocol safety or liveness",
	},

	{
		ID: "race", Scope: ScopeMessage, Category: CatConcurrency, Weight: 6,
		Pattern: re(`(?i)\b(data race|race condition|TOCTOU|time[ -]of[ -]check|torn (read|write)|lost wakeup|missed notification|non[ -]atomic (update|check))\b`),
		Desc:    "race condition",
	},

	{
		ID: "info-leak", Scope: ScopeMessage, Category: CatInfoLeak, Weight: 6,
		Pattern: re(`(?i)\b(information (leak|disclosure)|leak(s|ed|ing)? (memory|internal|sensitive|secret)|expos(e|es|ed|ing) (internal|secret|private)|logs? (the )?(secret|key|password|token))\b`),
		Desc:    "information disclosure",
	},

	{
		ID: "injection", Scope: ScopeMessage, Category: CatInjection, Weight: 9,
		Pattern: re(`(?i)\b(SQL injection|command injection|log injection|shell injection|path traversal|directory traversal|zip slip|XSS|cross[ -]site|CSRF|SSRF|XXE|prototype pollution|unsafe deserializ)\b`),
		Desc:    "injection class bug",
	},

	{
		ID: "supply-chain", Scope: ScopeMessage, Category: CatSupplyChain, Weight: 5,
		Pattern: re(`(?i)\b(dependenc(y|ies)|crate|package|version)\b.{0,40}\b(advisor(y|ies)|vulnerab(le|ility)|security (update|release|patch)|yanked)\b`),
		Desc:    "dependency security update",
	},

	// Meta rules shape the score without asserting a bug class of their own.
	{
		ID: "fix-shaped", Scope: ScopeMessage, Category: CatMeta, Weight: 2,
		Pattern: re(`(?i)((^|\n)\s*(\[[^\]]+\]\s*|[a-z0-9_.-]+(\([^)]*\))?[!:]\s*)?((cleanly|correctly|properly|safely|gracefully|strictly|explicitly)\s+)?(fix(es|ed|ing)?|prevent(s|ed|ing)?|reject(s|ed|ing)?|guard(s|ed|ing)?|harden(s|ed|ing)?|correct(s|ed|ing)?|patch(es|ed|ing)?|avoid(s|ed|ing)?|handle(s|d|ing)?|bound(s|ed|ing)?|limit(s|ed|ing)?|clamp(s|ed|ing)?|restrict(s|ed|ing)?|resolve(s|d|ing)?|sanitiz(e|es|ed|ing)|enforce(s|d|ing)?|ensure(s|d|ing)?|forbid(s|den|ding)?|disallow(s|ed|ing)?|don'?t panic|do not panic|no longer panic)\b|^[^\n]{0,120}\b(result(s|ed|ing)? in|caus(e|es|ed|ing))\b)`),
		Desc:    "phrased as a fix",
	},
	{
		ID: "neg-docs", Scope: ScopeMessage, Category: CatMeta, Weight: -5,
		Pattern: re(`(?i)^\s*(\[[^\]]+\]\s*)?(docs?|documentation|readme|comment|typo|spelling|changelog|website)\b`),
		Desc:    "documentation change",
	},
	{
		ID: "neg-refactor", Scope: ScopeMessage, Category: CatMeta, Weight: -4,
		Pattern: re(`(?i)^\s*(\[[^\]]+\]\s*|[a-z0-9_.-]+(\([^)]*\))?[!:]\s*)?(refactor(ing)?|rename(s|d)?|clean ?up|reorganiz|re-?structure|format(ting)?|rustfmt|clippy|style nit|remove dead code|simplif(y|ies|ied))\b`),
		Desc:    "refactor or cleanup",
	},
	{
		ID: "neg-test-only", Scope: ScopeMessage, Category: CatMeta, Weight: -3,
		Pattern: re(`(?i)^\s*(\[[^\]]+\]\s*|[a-z0-9_.-]+(\([^)]*\))?[!:]\s*)?(bench(mark)?s?|tests?|ci|chore|build|deps)\b`),
		Desc:    "test, bench, or CI change",
	},
	{
		ID: "neg-maintenance-subject", Scope: ScopeMessage, Category: CatMeta, Weight: -5,
		Pattern: re(`(?i)^[^\n]{0,160}\b(CI|build|compile)\b`),
		Desc:    "subject describes maintenance or test work",
	},
	{
		ID: "neg-mechanical-subject", Scope: ScopeMessage, Category: CatMeta, Weight: -8,
		Pattern: re(`(?i)^[^\n]{0,160}(\b(typos?|clippy|lints?|format(ting| strings?)?|warnings?|review comments|rebase|merge conflicts?)\b|\bresolve conflict\b)`),
		Desc:    "subject describes a mechanical change",
	},
	{
		ID: "neg-advisory-suppression", Scope: ScopeMessage, Category: CatMeta, Weight: -12,
		Pattern: re(`(?i)^\s*(\[[^\]]+\]\s*|[a-z0-9_.-]+(\([^)]*\))?[!:]\s*)?((ignore|allowlist|suppress)(d|es|ing)?|add (an )?exception for)\b.{0,80}\b(RUSTSEC|CVE|GHSA|advisory|audit)\b|^\s*add\b.{0,50}\b(RUSTSEC|CVE|GHSA)\b.{0,30}\b(audit )?ignores\b`),
		Desc:    "suppresses rather than fixes an advisory",
	},
	{
		ID: "neg-feature", Scope: ScopeMessage, Category: CatMeta, Weight: -3,
		Pattern: re(`(?i)^\s*(\[[^\]]+\]\s*)?(add|adds|added|introduce|implement|support|create|expose|migrate|move|port|upgrade|bump|release)\b`),
		Desc:    "feature or maintenance work",
	},
	{
		ID: "neg-revert", Scope: ScopeMessage, Category: CatMeta, Weight: -6,
		Pattern: re(`(?i)^\s*revert\b`),
		Desc:    "revert",
	},
}

// diffRules read the patch. They are weaker than message rules on their own,
// but they catch fixes whose message says nothing useful ("fix #123").
var diffRules = []Rule{
	{
		ID: "add-checked-arithmetic", Scope: ScopeAdded, Category: CatMemory, Weight: 3,
		Pattern: re(`\b(checked_(add|sub|mul|div|pow|neg|shl|shr)|saturating_(add|sub|mul)|overflowing_|wrapping_)\b`),
		Desc:    "adds overflow-safe arithmetic",
	},
	{
		ID: "add-fallible-conversion", Scope: ScopeAdded, Category: CatValidation, Weight: 2,
		Pattern: re(`\b(try_from|try_into|TryFrom|TryInto)\b`),
		Desc:    "adds a fallible conversion",
	},
	{
		ID: "add-safe-indexing", Scope: ScopeAdded, Category: CatValidation, Weight: 2,
		Pattern: re(`\.(get|get_mut|first|first_mut|last|last_mut)\s*\(`),
		Desc:    "adds bounds-checked indexing",
	},
	{
		ID: "add-limit", Scope: ScopeAdded, Category: CatDoS, Weight: 3,
		Pattern: re(`(?i)\b(max_(len|size|count|items|entries|bytes)|_MAX\b|too_(large|long|many|big)|TooLarge|TooLong|TooMany|InvalidLength|LengthLimit|with_capacity\([^)]*\.min\(|\.min\(|limit)\b`),
		Desc:    "adds a size or count limit",
	},
	{
		ID: "add-rejection", Scope: ScopeAdded, Category: CatValidation, Weight: 3,
		Pattern: re(`(?i)(return Err\(|Err\((Error::)?(Invalid|Malformed|TooLarge|Overflow|Unsupported|Duplicate|OutOfRange|Length)|bail!\(|ensure!\()`),
		Desc:    "adds an input rejection path",
	},
	{
		ID: "add-constant-time", Scope: ScopeAdded, Category: CatCrypto, Weight: 7,
		Pattern: re(`(?i)\b(ConstantTimeEq|ct_eq|subtle::|Zeroizing|zeroize|constant_time_eq|CtOption)\b`),
		Desc:    "adds constant-time or zeroizing code",
	},
	{
		ID: "add-ordering-check", Scope: ScopeAdded, Category: CatValidation, Weight: 3,
		Pattern: re(`(?i)(must ascend|ascending order|duplicate (key|entry|item)|non[ -]canonical|is_sorted|dedup)`),
		Desc:    "adds an ordering or duplicate check",
	},
	{
		ID: "remove-panic", Scope: ScopeRemoved, Category: CatDoS, Weight: 3,
		Pattern: re(`(\.unwrap\(\)|\.expect\(|panic!\(|unreachable!\(|todo!\(|\[[a-z_]+\.\.|as usize\])`),
		Desc:    "removes a panicking path",
	},
	{
		ID: "remove-unsafe", Scope: ScopeRemoved, Category: CatMemory, Weight: 4,
		Pattern: re(`\bunsafe\s*\{|\bfrom_raw|\btransmute\b|\bget_unchecked\b`),
		Desc:    "removes unsafe code",
	},
	{
		ID: "add-unsafe", Scope: ScopeAdded, Category: CatMemory, Weight: 1,
		Pattern: re(`\bunsafe\s*\{|\btransmute\b|\bget_unchecked\b`),
		Desc:    "touches unsafe code",
	},
}

// pathRules note that a commit touched code that parses or authenticates
// untrusted data. Their total contribution is capped by the scanner.
var pathRules = []Rule{
	{
		ID: "path-parsing", Scope: ScopePath, Category: CatValidation, Weight: 1,
		Pattern: re(`(?i)(codec|parse|parser|decode|decoding|deserial|wire|serial|format)`),
		Desc:    "parsing code",
	},
	{
		ID: "path-network", Scope: ScopePath, Category: CatValidation, Weight: 1,
		Pattern: re(`(?i)(/p2p/|/net|network|stream|socket|handshake|transport|dialer|listener|rpc)`),
		Desc:    "network-facing code",
	},
	{
		ID: "path-crypto", Scope: ScopePath, Category: CatCrypto, Weight: 1,
		Pattern: re(`(?i)(crypto|signature|signer|verif|bls|ed25519|secp|dkg|threshold|hash|merkle|mmr|zk)`),
		Desc:    "cryptographic code",
	},
	{
		ID: "path-consensus", Scope: ScopePath, Category: CatAuthz, Weight: 1,
		Pattern: re(`(?i)(consensus|simplex|threshold|validator|elector|quorum|vote|finaliz)`),
		Desc:    "consensus code",
	},
}

// Default returns every rule in evaluation order.
func Default() []Rule {
	all := make([]Rule, 0, len(messageRules)+len(diffRules)+len(pathRules))
	all = append(all, messageRules...)
	all = append(all, diffRules...)
	all = append(all, pathRules...)
	return all
}

// ByScope returns the rules that apply to one scope.
func ByScope(all []Rule, scope Scope) []Rule {
	out := make([]Rule, 0, len(all))
	for _, r := range all {
		if r.Scope == scope {
			out = append(out, r)
		}
	}
	return out
}
