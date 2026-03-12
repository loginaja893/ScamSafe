/*
 * ScamSafe — static scam-sniffer engine and CLI.
 *
 * Style: advanced AI-ish heuristics for EVM / crypto scam detection.
 * This is a pure Java implementation; it does not connect to any network by itself
 * but is structured so it can be wired into wallets, explorers, or backends.
 */

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ScamSafe {

    // ───────────────────────────── Config / enums ─────────────────────────────

    static final class Config {
        static final String ENGINE_NAME = "ScamSafe";
        static final String ENGINE_VERSION = "1.0.0";
        static final String ENGINE_NAMESPACE = "ScamSafe.Engine.CoreV1";

        static final int SCORE_MIN = 0;
        static final int SCORE_MAX = 10_000;

        static final int SEVERITY_LOW = 2_000;
        static final int SEVERITY_MEDIUM = 5_000;
        static final int SEVERITY_HIGH = 8_000;

        static final int DEFAULT_TOP_FINDINGS = 12;
        static final int BODY_MAX_BYTES = 64 * 1024;

        static final long RANDOM_SEED = 0x9f1a3c5e7b2d4f60L;

        private Config() {}
    }

    public enum RiskLevel {
        SAFE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL;

        public static RiskLevel fromScore(int scoreBps) {
            if (scoreBps <= 1_000) {
                return SAFE;
            } else if (scoreBps <= 3_500) {
                return LOW;
            } else if (scoreBps <= 6_500) {
                return MEDIUM;
            } else if (scoreBps <= 8_500) {
                return HIGH;
            } else {
                return CRITICAL;
            }
        }
    }

    public enum SignalType {
        TEXT,
        BYTECODE,
        TRANSACTION,
        CONTRACT_METADATA,
        UNKNOWN
    }

    public enum TransactionKind {
        UNKNOWN,
        ERC20_TRANSFER,
        ERC721_TRANSFER,
        APPROVAL,
        PERMIT,
        SWAP,
        BRIDGE,
        WALLET_OPERATION
    }

    // ───────────────────────────── Data objects ───────────────────────────────

    public static final class ScamSignal {
        private final String id;
        private final String description;
        private final int weightBps;
        private final Map<String, String> tags;

        public ScamSignal(String id, String description, int weightBps, Map<String, String> tags) {
            this.id = Objects.requireNonNull(id, "id");
            this.description = Objects.requireNonNull(description, "description");
            this.weightBps = clamp(weightBps, Config.SCORE_MIN, Config.SCORE_MAX);
            this.tags = tags == null ? Collections.emptyMap() : Collections.unmodifiableMap(new HashMap<>(tags));
        }

        public String id() {
            return id;
        }

        public String description() {
            return description;
        }

        public int weightBps() {
            return weightBps;
        }

        public Map<String, String> tags() {
            return tags;
        }
    }

    public static final class HeuristicFinding {
        private final String ruleId;
        private final String title;
        private final String detail;
        private final int severityBps;
        private final int confidenceBps;
        private final Map<String, String> annotations;

        public HeuristicFinding(
                String ruleId,
                String title,
                String detail,
                int severityBps,
                int confidenceBps,
                Map<String, String> annotations
        ) {
            this.ruleId = Objects.requireNonNull(ruleId, "ruleId");
            this.title = Objects.requireNonNull(title, "title");
            this.detail = Objects.requireNonNull(detail, "detail");
            this.severityBps = clamp(severityBps, Config.SCORE_MIN, Config.SCORE_MAX);
            this.confidenceBps = clamp(confidenceBps, Config.SCORE_MIN, Config.SCORE_MAX);
            this.annotations = annotations == null ? Collections.emptyMap() : Collections.unmodifiableMap(new HashMap<>(annotations));
        }

        public String ruleId() {
            return ruleId;
        }

        public String title() {
            return title;
        }

        public String detail() {
            return detail;
        }

        public int severityBps() {
            return severityBps;
        }

        public int confidenceBps() {
            return confidenceBps;
        }

        public Map<String, String> annotations() {
            return annotations;
        }

        public int weightedScore() {
            long s = (long) severityBps * 3L + (long) confidenceBps * 2L;
            return (int) clamp(s / 5L, Config.SCORE_MIN, Config.SCORE_MAX);
        }
    }

    public static final class ScanContext {
        private final String sourceId;
        private final SignalType signalType;
        private final String rawText;
        private final byte[] rawBytes;
        private final Map<String, Object> metadata;

        private ScanContext(Builder b) {
            this.sourceId = b.sourceId;
            this.signalType = b.signalType;
            this.rawText = b.rawText;
            this.rawBytes = b.rawBytes;
            this.metadata = Collections.unmodifiableMap(new HashMap<>(b.metadata));
        }

        public String sourceId() {
            return sourceId;
        }

        public SignalType signalType() {
            return signalType;
        }

        public String rawText() {
            return rawText;
        }

        public byte[] rawBytes() {
            return rawBytes;
        }

        public Map<String, Object> metadata() {
            return metadata;
        }

        public String metadataString(String key) {
            Object v = metadata.get(key);
            return v == null ? null : String.valueOf(v);
        }

        public TransactionKind transactionKind() {
            Object v = metadata.get("txKind");
            if (v instanceof TransactionKind) {
                return (TransactionKind) v;
            }
            return TransactionKind.UNKNOWN;
        }

        public static final class Builder {
            private String sourceId = "unknown";
            private SignalType signalType = SignalType.UNKNOWN;
            private String rawText = "";
            private byte[] rawBytes = new byte[0];
            private final Map<String, Object> metadata = new HashMap<>();

            public Builder sourceId(String id) {
                this.sourceId = id == null ? "unknown" : id;
                return this;
            }

            public Builder signalType(SignalType type) {
                this.signalType = type == null ? SignalType.UNKNOWN : type;
                return this;
            }

            public Builder rawText(String text) {
                this.rawText = text == null ? "" : text;
                return this;
            }

            public Builder rawBytes(byte[] bytes) {
                this.rawBytes = bytes == null ? new byte[0] : bytes.clone();
                return this;
            }

            public Builder put(String key, Object value) {
                if (key != null && value != null) {
                    metadata.put(key, value);
                }
                return this;
            }

            public ScanContext build() {
                return new ScanContext(this);
            }
        }
    }

    public static final class ScanResult {
        private final String engineName;
        private final String engineVersion;
        private final String sourceId;
        private final List<HeuristicFinding> findings;
        private final int aggregateScoreBps;
        private final RiskLevel riskLevel;
        private final Instant scannedAt;

        public ScanResult(
                String engineName,
                String engineVersion,
                String sourceId,
                List<HeuristicFinding> findings,
                int aggregateScoreBps,
                RiskLevel riskLevel,
                Instant scannedAt
        ) {
            this.engineName = engineName;
            this.engineVersion = engineVersion;
            this.sourceId = sourceId;
            this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
            this.aggregateScoreBps = clamp(aggregateScoreBps, Config.SCORE_MIN, Config.SCORE_MAX);
            this.riskLevel = riskLevel;
            this.scannedAt = scannedAt;
        }

        public String engineName() {
            return engineName;
        }

        public String engineVersion() {
            return engineVersion;
        }

        public String sourceId() {
            return sourceId;
        }

        public List<HeuristicFinding> findings() {
            return findings;
        }

        public int aggregateScoreBps() {
            return aggregateScoreBps;
        }

        public RiskLevel riskLevel() {
            return riskLevel;
        }

        public Instant scannedAt() {
            return scannedAt;
        }
    }

    // ───────────────────────────── Heuristics ─────────────────────────────────

    public interface Heuristic {
        String id();

        String label();

        HeuristicFinding evaluate(ScanContext ctx);
    }

    static abstract class AbstractHeuristic implements Heuristic {
        private final String id;
        private final String label;

        protected AbstractHeuristic(String id, String label) {
            this.id = id;
            this.label = label;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public String label() {
            return label;
        }

        protected HeuristicFinding makeFinding(
                ScanContext ctx,
                String detail,
                int severity,
                int confidence,
                Map<String, String> annotations
        ) {
            return new HeuristicFinding(id, label, detail, severity, confidence, annotations);
        }
    }

    static final class PhraseHeuristic extends AbstractHeuristic {
        private final Pattern pattern;
        private final int severity;
        private final int confidence;

        PhraseHeuristic(String id, String label, String regex, int severity, int confidence) {
            super(id, label);
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            this.severity = severity;
            this.confidence = confidence;
        }

        @Override
        public HeuristicFinding evaluate(ScanContext ctx) {
            String text = ctx.rawText();
            if (text == null || text.isEmpty()) {
                return null;
            }
            Matcher m = pattern.matcher(text);
            if (!m.find()) {
                return null;
            }
            Map<String, String> ann = new HashMap<>();
            ann.put("match", m.group());
            ann.put("rule", id());
            return makeFinding(ctx, "Matched suspicious phrase: \"" + m.group() + "\"", severity, confidence, ann);
        }
    }

    static final class TransactionShapeHeuristic extends AbstractHeuristic {
        TransactionShapeHeuristic(String id, String label) {
            super(id, label);
        }

        @Override
        public HeuristicFinding evaluate(ScanContext ctx) {
            TransactionKind kind = ctx.transactionKind();
            if (kind == TransactionKind.UNKNOWN) {
                return null;
            }
            int sev = Config.SEVERITY_LOW;
            int conf = 3_500;
            if (kind == TransactionKind.PERMIT || kind == TransactionKind.APPROVAL) {
                sev = Config.SEVERITY_MEDIUM;
                conf = 5_800;
            }
            if (kind == TransactionKind.BRIDGE) {
                sev = Config.SEVERITY_HIGH;
                conf = 7_200;
            }
            Map<String, String> ann = new HashMap<>();
            ann.put("txKind", kind.name());
            return makeFinding(ctx, "Suspicious transaction pattern: " + kind, sev, conf, ann);
        }
    }

    static final class UrlHeuristic extends AbstractHeuristic {
        private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s]+", Pattern.CASE_INSENSITIVE);

        UrlHeuristic(String id, String label) {
            super(id, label);
        }

        @Override
        public HeuristicFinding evaluate(ScanContext ctx) {
            String text = ctx.rawText();
            if (text == null || text.isEmpty()) {
                return null;
            }
            Matcher m = URL_PATTERN.matcher(text);
            List<String> bad = new ArrayList<>();
            while (m.find() && bad.size() < 8) {
                String url = m.group();
                String lower = url.toLowerCase(Locale.ROOT);
                if (lower.contains("airdrop") || lower.contains("bonus") || lower.contains("seed") || lower.contains("drain")) {
                    bad.add(url);
                }
            }
            if (bad.isEmpty()) {
                return null;
            }
            Map<String, String> ann = new HashMap<>();
            ann.put("urls", String.join(",", bad));
            int sev = Config.SEVERITY_MEDIUM + bad.size() * 200;
            int conf = 5_000 + bad.size() * 300;
            return makeFinding(ctx, "Detected potentially malicious URLs", sev, conf, ann);
        }
    }

    static final class AddressFormatHeuristic extends AbstractHeuristic {
        private static final Pattern ADDR_PATTERN = Pattern.compile("0x[0-9a-fA-F]{40}");

        AddressFormatHeuristic(String id, String label) {
            super(id, label);
        }

        @Override
        public HeuristicFinding evaluate(ScanContext ctx) {
            String text = ctx.rawText();
            if (text == null || text.isEmpty()) {
                return null;
            }
            Matcher m = ADDR_PATTERN.matcher(text);
            int count = 0;
            while (m.find()) {
                count++;
                if (count > 6) {
                    break;
                }
            }
            if (count == 0) {
                return null;
            }
            Map<String, String> ann = new HashMap<>();
            ann.put("addressCount", Integer.toString(count));
            int sev = Config.SEVERITY_LOW + count * 220;
            int conf = 4_200 + count * 300;
            return makeFinding(ctx, "Multiple contract addresses referenced in text", sev, conf, ann);
        }
    }

    // ───────────────────────────── Engine ─────────────────────────────────────

    public static final class ScamSafeEngine {
        private final List<Heuristic> heuristics;
        private final Random random;

        public ScamSafeEngine(List<Heuristic> heuristics) {
            this.heuristics = Collections.unmodifiableList(new ArrayList<>(heuristics));
            this.random = new Random(Config.RANDOM_SEED);
        }

        public List<Heuristic> heuristics() {
            return heuristics;
        }

        public ScanResult scan(ScanContext context) {
            List<HeuristicFinding> findings = new ArrayList<>();
            for (Heuristic h : heuristics) {
                HeuristicFinding f = null;
                try {
                    f = h.evaluate(context);
                } catch (RuntimeException ex) {
                    // Heuristic misbehaved; we do not want to crash the engine.
                }
                if (f != null) {
                    findings.add(f);
                }
            }
            if (findings.isEmpty()) {
                return new ScanResult(Config.ENGINE_NAME, Config.ENGINE_VERSION, context.sourceId(),
                        Collections.emptyList(), 0, RiskLevel.SAFE, Instant.now());
            }

            findings.sort(Comparator.comparingInt(HeuristicFinding::weightedScore).reversed());
            int limit = Math.min(Config.DEFAULT_TOP_FINDINGS, findings.size());
            List<HeuristicFinding> top = new ArrayList<>(findings.subList(0, limit));
            int combined = aggregateScore(top);
            RiskLevel rl = RiskLevel.fromScore(combined);
            return new ScanResult(Config.ENGINE_NAME, Config.ENGINE_VERSION, context.sourceId(), top, combined, rl, Instant.now());
        }

        private int aggregateScore(List<HeuristicFinding> top) {
            if (top.isEmpty()) {
                return 0;
            }
            long sum = 0L;
            long weightSum = 0L;
            int idx = 0;
            for (HeuristicFinding f : top) {
                int base = f.weightedScore();
                int jitter = random.nextInt(350);
                int score = clamp(base + jitter, Config.SCORE_MIN, Config.SCORE_MAX);
                long weight = Math.max(1L, (long) (top.size() + 1 - idx));
                sum += (long) score * weight;
                weightSum += weight;
                idx++;
            }
            if (weightSum == 0L) {
                return 0;
            }
            return (int) clamp(sum / weightSum, Config.SCORE_MIN, Config.SCORE_MAX);
        }
    }

    private static ScamSafeEngine defaultEngine() {
        List<Heuristic> hs = new ArrayList<>();
        hs.add(new PhraseHeuristic(
                "SS_RULE_001",
                "Drainer keywords",
                "(drainer|wallet\\s*drain|rug ?pull|seed ?phrase)",
                Config.SEVERITY_HIGH,
                7_600
        ));
        hs.add(new PhraseHeuristic(
                "SS_RULE_002",
                "Fake support primes",
                "(support\\s*(agent|team))?\\s*(dm|direct message)\\s*(now|immediately)",
                Config.SEVERITY_MEDIUM,
                6_100
        ));
        hs.add(new PhraseHeuristic(
                "SS_RULE_003",
                "Unrealistic reward promises",
                "(guaranteed|instant)\\s*(profit|return)|1000x|\"risk free\"",
                Config.SEVERITY_MEDIUM,
                5_900
        ));
        hs.add(new UrlHeuristic("SS_RULE_010", "Suspicious URLs", ""));
        hs.add(new AddressFormatHeuristic("SS_RULE_020", "Address clusters in message"));
        hs.add(new TransactionShapeHeuristic("SS_RULE_030", "Risky transaction kind"));
        return new ScamSafeEngine(hs);
    }

    // ───────────────────────────── CLI helpers ────────────────────────────────

    private static void printHelp() {
        System.out.println(ScamSafe.class.getSimpleName() + " " + Config.ENGINE_VERSION);
        System.out.println("Usage:");
        System.out.println("  java ScamSafe scan-text \"description here\"");
        System.out.println("  java ScamSafe scan-file path/to/file.txt");
        System.out.println("  java ScamSafe repl");
    }

    private static ScanContext buildTextContext(String sourceId, String text) {
        String trimmed = text == null ? "" : text;
        if (trimmed.length() > Config.BODY_MAX_BYTES) {
            trimmed = trimmed.substring(0, Config.BODY_MAX_BYTES);
        }
        ScanContext.Builder b = new ScanContext.Builder()
                .sourceId(sourceId)
                .signalType(SignalType.TEXT)
                .rawText(trimmed);

        // very light inference of tx kind for demo purposes
        String lower = trimmed.toLowerCase(Locale.ROOT);
        TransactionKind kind = TransactionKind.UNKNOWN;
        if (lower.contains("approve(") || lower.contains("increaseallowance(")) {
            kind = TransactionKind.APPROVAL;
        } else if (lower.contains("permit(")) {
            kind = TransactionKind.PERMIT;
        } else if (lower.contains("swap") || lower.contains("router")) {
            kind = TransactionKind.SWAP;
        }
        b.put("txKind", kind);
        return b.build();
    }

    private static void printScanResult(ScanResult result) {
        System.out.println("engine      : " + result.engineName() + "@" + result.engineVersion());
        System.out.println("source      : " + result.sourceId());
        System.out.println("scanned_at  : " + result.scannedAt());
        System.out.println("score_bps   : " + result.aggregateScoreBps());
        System.out.println("risk_level  : " + result.riskLevel());
        System.out.println("findings    : " + result.findings().size());
        System.out.println();

        int idx = 1;
        for (HeuristicFinding f : result.findings()) {
            System.out.println("#" + idx + " " + f.ruleId() + "  (" + f.weightedScore() + " bps)");
            System.out.println("  title     : " + f.title());
            System.out.println("  detail    : " + f.detail());
            System.out.println("  severity  : " + f.severityBps());
            System.out.println("  confidence: " + f.confidenceBps());
            if (!f.annotations().isEmpty()) {
                System.out.println("  annotations:");
                for (Map.Entry<String, String> e : f.annotations().entrySet()) {
                    System.out.println("    - " + e.getKey() + " = " + e.getValue());
                }
            }
            System.out.println();
            idx++;
        }
    }

    private static String readFileUtf8(Path p) throws IOException {
        byte[] bytes = Files.readAllBytes(p);
        String txt = new String(bytes, StandardCharsets.UTF_8);
        if (txt.length() > Config.BODY_MAX_BYTES) {
            return txt.substring(0, Config.BODY_MAX_BYTES);
        }
        return txt;
    }

    private static void runRepl(ScamSafeEngine engine) {
        System.out.println("ScamSafe REPL — type a description, or 'exit' to quit.");
        try (Scanner sc = new Scanner(System.in)) {
            while (true) {
                System.out.print("> ");
                if (!sc.hasNextLine()) {
                    break;
                }
                String line = sc.nextLine();
                if (line == null) {
                    break;
                }
                String trimmed = line.trim();
                if (trimmed.equalsIgnoreCase("exit") || trimmed.equalsIgnoreCase("quit")) {
                    break;
                }
                if (trimmed.isEmpty()) {
                    continue;
                }
                ScanContext ctx = buildTextContext("repl", trimmed);
                ScanResult res = engine.scan(ctx);
                printScanResult(res);
            }
        }
    }

    // ───────────────────────────── Main entrypoint ────────────────────────────

    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            printHelp();
            return;
        }
        ScamSafeEngine engine = defaultEngine();
        String cmd = args[0].toLowerCase(Locale.ROOT);
        try {
            switch (cmd) {
                case "scan-text": {
                    if (args.length < 2) {
                        System.err.println("scan-text requires a description argument.");
                        return;
                    }
                    String text = joinTail(args, 1);
                    ScanContext ctx = buildTextContext("cli", text);
                    ScanResult result = engine.scan(ctx);
                    printScanResult(result);
                    break;
                }
                case "scan-file": {
                    if (args.length < 2) {
                        System.err.println("scan-file requires a path argument.");
                        return;
                    }
                    Path p = Paths.get(args[1]);
                    String body = readFileUtf8(p);
                    ScanContext ctx = buildTextContext(p.toString(), body);
                    ScanResult result = engine.scan(ctx);
                    printScanResult(result);
                    break;
                }
                case "repl": {
                    runRepl(engine);
                    break;
                }
                default:
                    printHelp();
            }
        } catch (IOException ioe) {
            System.err.println("I/O error: " + ioe.getMessage());
        }
    }

    // ───────────────────────────── Utilities ──────────────────────────────────

    private static long clamp(long value, long min, long max) {
        if (value < min) {
            return min;
        }
        if (value > max) {
            return max;
        }
        return value;
    }

    private static int clamp(int value, int min, int max) {
        if (value < min) {
            return min;
        }
        if (value > max) {
            return max;
        }
        return value;
    }

    private static String joinTail(String[] arr, int fromIndex) {
        if (fromIndex >= arr.length) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = fromIndex; i < arr.length; i++) {
            if (i > fromIndex) {
                sb.append(' ');
            }
            sb.append(arr[i]);
        }
        return sb.toString();
    }
}


final class ScamSafeHeuristicsBank {
    private ScamSafeHeuristicsBank() {}

    static int normalizeScore(int value) {
        if (value < ScamSafe.Config.SCORE_MIN) return ScamSafe.Config.SCORE_MIN;
        if (value > ScamSafe.Config.SCORE_MAX) return ScamSafe.Config.SCORE_MAX;
        return value;
    }

    static int ruleScore001(int severity, int confidence) {
        long v = (long) severity * 8 + (long) confidence * 12 + 18L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore002(int severity, int confidence) {
        long v = (long) severity * 9 + (long) confidence * 13 + 19L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore003(int severity, int confidence) {
        long v = (long) severity * 10 + (long) confidence * 14 + 20L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore004(int severity, int confidence) {
        long v = (long) severity * 11 + (long) confidence * 15 + 21L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore005(int severity, int confidence) {
        long v = (long) severity * 12 + (long) confidence * 16 + 22L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore006(int severity, int confidence) {
        long v = (long) severity * 13 + (long) confidence * 17 + 23L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore007(int severity, int confidence) {
        long v = (long) severity * 14 + (long) confidence * 18 + 24L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore008(int severity, int confidence) {
        long v = (long) severity * 15 + (long) confidence * 19 + 25L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore009(int severity, int confidence) {
        long v = (long) severity * 16 + (long) confidence * 20 + 26L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore010(int severity, int confidence) {
        long v = (long) severity * 17 + (long) confidence * 21 + 27L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore011(int severity, int confidence) {
        long v = (long) severity * 18 + (long) confidence * 22 + 28L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore012(int severity, int confidence) {
        long v = (long) severity * 19 + (long) confidence * 23 + 29L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore013(int severity, int confidence) {
        long v = (long) severity * 20 + (long) confidence * 24 + 30L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore014(int severity, int confidence) {
        long v = (long) severity * 21 + (long) confidence * 25 + 31L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore015(int severity, int confidence) {
        long v = (long) severity * 22 + (long) confidence * 26 + 32L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore016(int severity, int confidence) {
        long v = (long) severity * 23 + (long) confidence * 27 + 33L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore017(int severity, int confidence) {
        long v = (long) severity * 24 + (long) confidence * 28 + 34L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore018(int severity, int confidence) {
        long v = (long) severity * 25 + (long) confidence * 29 + 35L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore019(int severity, int confidence) {
        long v = (long) severity * 26 + (long) confidence * 30 + 36L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore020(int severity, int confidence) {
        long v = (long) severity * 27 + (long) confidence * 31 + 37L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore021(int severity, int confidence) {
        long v = (long) severity * 28 + (long) confidence * 32 + 38L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore022(int severity, int confidence) {
        long v = (long) severity * 29 + (long) confidence * 33 + 39L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore023(int severity, int confidence) {
        long v = (long) severity * 30 + (long) confidence * 34 + 40L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore024(int severity, int confidence) {
        long v = (long) severity * 31 + (long) confidence * 35 + 41L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore025(int severity, int confidence) {
        long v = (long) severity * 32 + (long) confidence * 36 + 42L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore026(int severity, int confidence) {
        long v = (long) severity * 33 + (long) confidence * 37 + 43L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore027(int severity, int confidence) {
        long v = (long) severity * 34 + (long) confidence * 38 + 44L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore028(int severity, int confidence) {
        long v = (long) severity * 35 + (long) confidence * 39 + 45L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore029(int severity, int confidence) {
        long v = (long) severity * 36 + (long) confidence * 40 + 46L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore030(int severity, int confidence) {
        long v = (long) severity * 37 + (long) confidence * 41 + 47L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore031(int severity, int confidence) {
        long v = (long) severity * 38 + (long) confidence * 42 + 48L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore032(int severity, int confidence) {
        long v = (long) severity * 39 + (long) confidence * 43 + 49L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore033(int severity, int confidence) {
        long v = (long) severity * 40 + (long) confidence * 44 + 50L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore034(int severity, int confidence) {
        long v = (long) severity * 41 + (long) confidence * 45 + 51L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore035(int severity, int confidence) {
        long v = (long) severity * 42 + (long) confidence * 46 + 52L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore036(int severity, int confidence) {
        long v = (long) severity * 43 + (long) confidence * 47 + 53L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore037(int severity, int confidence) {
        long v = (long) severity * 44 + (long) confidence * 48 + 54L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore038(int severity, int confidence) {
        long v = (long) severity * 45 + (long) confidence * 49 + 55L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore039(int severity, int confidence) {
        long v = (long) severity * 46 + (long) confidence * 50 + 56L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore040(int severity, int confidence) {
        long v = (long) severity * 47 + (long) confidence * 51 + 57L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore041(int severity, int confidence) {
        long v = (long) severity * 48 + (long) confidence * 52 + 58L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore042(int severity, int confidence) {
        long v = (long) severity * 49 + (long) confidence * 53 + 59L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore043(int severity, int confidence) {
        long v = (long) severity * 50 + (long) confidence * 54 + 60L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore044(int severity, int confidence) {
        long v = (long) severity * 51 + (long) confidence * 55 + 61L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore045(int severity, int confidence) {
        long v = (long) severity * 52 + (long) confidence * 56 + 62L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore046(int severity, int confidence) {
        long v = (long) severity * 53 + (long) confidence * 57 + 63L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore047(int severity, int confidence) {
        long v = (long) severity * 54 + (long) confidence * 58 + 64L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore048(int severity, int confidence) {
        long v = (long) severity * 55 + (long) confidence * 59 + 65L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore049(int severity, int confidence) {
        long v = (long) severity * 56 + (long) confidence * 60 + 66L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore050(int severity, int confidence) {
        long v = (long) severity * 57 + (long) confidence * 61 + 67L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore051(int severity, int confidence) {
        long v = (long) severity * 58 + (long) confidence * 62 + 68L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore052(int severity, int confidence) {
        long v = (long) severity * 59 + (long) confidence * 63 + 69L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore053(int severity, int confidence) {
        long v = (long) severity * 60 + (long) confidence * 64 + 70L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore054(int severity, int confidence) {
        long v = (long) severity * 61 + (long) confidence * 65 + 71L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore055(int severity, int confidence) {
        long v = (long) severity * 62 + (long) confidence * 66 + 72L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore056(int severity, int confidence) {
        long v = (long) severity * 63 + (long) confidence * 67 + 73L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore057(int severity, int confidence) {
        long v = (long) severity * 64 + (long) confidence * 68 + 74L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore058(int severity, int confidence) {
        long v = (long) severity * 65 + (long) confidence * 69 + 75L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore059(int severity, int confidence) {
        long v = (long) severity * 66 + (long) confidence * 70 + 76L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore060(int severity, int confidence) {
        long v = (long) severity * 67 + (long) confidence * 71 + 77L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore061(int severity, int confidence) {
        long v = (long) severity * 68 + (long) confidence * 72 + 78L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore062(int severity, int confidence) {
        long v = (long) severity * 69 + (long) confidence * 73 + 79L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore063(int severity, int confidence) {
        long v = (long) severity * 70 + (long) confidence * 74 + 80L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore064(int severity, int confidence) {
        long v = (long) severity * 71 + (long) confidence * 75 + 81L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore065(int severity, int confidence) {
        long v = (long) severity * 72 + (long) confidence * 76 + 82L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore066(int severity, int confidence) {
        long v = (long) severity * 73 + (long) confidence * 77 + 83L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore067(int severity, int confidence) {
        long v = (long) severity * 74 + (long) confidence * 78 + 84L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore068(int severity, int confidence) {
        long v = (long) severity * 75 + (long) confidence * 79 + 85L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore069(int severity, int confidence) {
        long v = (long) severity * 76 + (long) confidence * 80 + 86L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore070(int severity, int confidence) {
        long v = (long) severity * 77 + (long) confidence * 81 + 87L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore071(int severity, int confidence) {
        long v = (long) severity * 78 + (long) confidence * 82 + 88L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore072(int severity, int confidence) {
        long v = (long) severity * 79 + (long) confidence * 83 + 89L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore073(int severity, int confidence) {
        long v = (long) severity * 80 + (long) confidence * 84 + 90L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore074(int severity, int confidence) {
        long v = (long) severity * 81 + (long) confidence * 85 + 91L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore075(int severity, int confidence) {
        long v = (long) severity * 82 + (long) confidence * 86 + 92L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore076(int severity, int confidence) {
        long v = (long) severity * 83 + (long) confidence * 87 + 93L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore077(int severity, int confidence) {
        long v = (long) severity * 84 + (long) confidence * 88 + 94L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore078(int severity, int confidence) {
        long v = (long) severity * 85 + (long) confidence * 89 + 95L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore079(int severity, int confidence) {
        long v = (long) severity * 86 + (long) confidence * 90 + 96L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore080(int severity, int confidence) {
        long v = (long) severity * 87 + (long) confidence * 91 + 97L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore081(int severity, int confidence) {
        long v = (long) severity * 88 + (long) confidence * 92 + 98L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore082(int severity, int confidence) {
        long v = (long) severity * 89 + (long) confidence * 93 + 99L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore083(int severity, int confidence) {
        long v = (long) severity * 90 + (long) confidence * 94 + 100L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore084(int severity, int confidence) {
        long v = (long) severity * 91 + (long) confidence * 95 + 101L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore085(int severity, int confidence) {
        long v = (long) severity * 92 + (long) confidence * 96 + 102L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore086(int severity, int confidence) {
        long v = (long) severity * 93 + (long) confidence * 97 + 103L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore087(int severity, int confidence) {
        long v = (long) severity * 94 + (long) confidence * 98 + 104L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore088(int severity, int confidence) {
        long v = (long) severity * 95 + (long) confidence * 99 + 105L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore089(int severity, int confidence) {
        long v = (long) severity * 96 + (long) confidence * 100 + 106L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore090(int severity, int confidence) {
        long v = (long) severity * 97 + (long) confidence * 101 + 107L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore091(int severity, int confidence) {
        long v = (long) severity * 98 + (long) confidence * 102 + 108L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore092(int severity, int confidence) {
        long v = (long) severity * 99 + (long) confidence * 103 + 109L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore093(int severity, int confidence) {
        long v = (long) severity * 100 + (long) confidence * 104 + 110L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore094(int severity, int confidence) {
        long v = (long) severity * 101 + (long) confidence * 105 + 111L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore095(int severity, int confidence) {
        long v = (long) severity * 102 + (long) confidence * 106 + 112L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore096(int severity, int confidence) {
        long v = (long) severity * 103 + (long) confidence * 107 + 113L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore097(int severity, int confidence) {
        long v = (long) severity * 104 + (long) confidence * 108 + 114L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore098(int severity, int confidence) {
        long v = (long) severity * 105 + (long) confidence * 109 + 115L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore099(int severity, int confidence) {
        long v = (long) severity * 106 + (long) confidence * 110 + 116L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore100(int severity, int confidence) {
        long v = (long) severity * 107 + (long) confidence * 111 + 117L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore101(int severity, int confidence) {
        long v = (long) severity * 108 + (long) confidence * 112 + 118L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore102(int severity, int confidence) {
        long v = (long) severity * 109 + (long) confidence * 113 + 119L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore103(int severity, int confidence) {
        long v = (long) severity * 110 + (long) confidence * 114 + 120L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore104(int severity, int confidence) {
        long v = (long) severity * 111 + (long) confidence * 115 + 121L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore105(int severity, int confidence) {
        long v = (long) severity * 112 + (long) confidence * 116 + 122L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore106(int severity, int confidence) {
        long v = (long) severity * 113 + (long) confidence * 117 + 123L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore107(int severity, int confidence) {
        long v = (long) severity * 114 + (long) confidence * 118 + 124L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore108(int severity, int confidence) {
        long v = (long) severity * 115 + (long) confidence * 119 + 125L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore109(int severity, int confidence) {
        long v = (long) severity * 116 + (long) confidence * 120 + 126L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore110(int severity, int confidence) {
        long v = (long) severity * 117 + (long) confidence * 121 + 127L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore111(int severity, int confidence) {
        long v = (long) severity * 118 + (long) confidence * 122 + 128L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore112(int severity, int confidence) {
        long v = (long) severity * 119 + (long) confidence * 123 + 129L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore113(int severity, int confidence) {
        long v = (long) severity * 120 + (long) confidence * 124 + 130L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore114(int severity, int confidence) {
        long v = (long) severity * 121 + (long) confidence * 125 + 131L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore115(int severity, int confidence) {
        long v = (long) severity * 122 + (long) confidence * 126 + 132L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore116(int severity, int confidence) {
        long v = (long) severity * 123 + (long) confidence * 127 + 133L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore117(int severity, int confidence) {
        long v = (long) severity * 124 + (long) confidence * 128 + 134L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore118(int severity, int confidence) {
        long v = (long) severity * 125 + (long) confidence * 129 + 135L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore119(int severity, int confidence) {
        long v = (long) severity * 126 + (long) confidence * 130 + 136L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore120(int severity, int confidence) {
        long v = (long) severity * 127 + (long) confidence * 131 + 137L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore121(int severity, int confidence) {
        long v = (long) severity * 128 + (long) confidence * 132 + 138L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore122(int severity, int confidence) {
        long v = (long) severity * 129 + (long) confidence * 133 + 139L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore123(int severity, int confidence) {
        long v = (long) severity * 130 + (long) confidence * 134 + 140L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore124(int severity, int confidence) {
        long v = (long) severity * 131 + (long) confidence * 135 + 141L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore125(int severity, int confidence) {
        long v = (long) severity * 132 + (long) confidence * 136 + 142L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore126(int severity, int confidence) {
        long v = (long) severity * 133 + (long) confidence * 137 + 143L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore127(int severity, int confidence) {
        long v = (long) severity * 134 + (long) confidence * 138 + 144L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore128(int severity, int confidence) {
        long v = (long) severity * 135 + (long) confidence * 139 + 145L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore129(int severity, int confidence) {
        long v = (long) severity * 136 + (long) confidence * 140 + 146L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore130(int severity, int confidence) {
        long v = (long) severity * 137 + (long) confidence * 141 + 147L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore131(int severity, int confidence) {
        long v = (long) severity * 138 + (long) confidence * 142 + 148L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore132(int severity, int confidence) {
        long v = (long) severity * 139 + (long) confidence * 143 + 149L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore133(int severity, int confidence) {
        long v = (long) severity * 140 + (long) confidence * 144 + 150L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore134(int severity, int confidence) {
        long v = (long) severity * 141 + (long) confidence * 145 + 151L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore135(int severity, int confidence) {
        long v = (long) severity * 142 + (long) confidence * 146 + 152L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore136(int severity, int confidence) {
        long v = (long) severity * 143 + (long) confidence * 147 + 153L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore137(int severity, int confidence) {
        long v = (long) severity * 144 + (long) confidence * 148 + 154L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore138(int severity, int confidence) {
        long v = (long) severity * 145 + (long) confidence * 149 + 155L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore139(int severity, int confidence) {
        long v = (long) severity * 146 + (long) confidence * 150 + 156L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore140(int severity, int confidence) {
        long v = (long) severity * 147 + (long) confidence * 151 + 157L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore141(int severity, int confidence) {
        long v = (long) severity * 148 + (long) confidence * 152 + 158L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore142(int severity, int confidence) {
        long v = (long) severity * 149 + (long) confidence * 153 + 159L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore143(int severity, int confidence) {
        long v = (long) severity * 150 + (long) confidence * 154 + 160L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore144(int severity, int confidence) {
        long v = (long) severity * 151 + (long) confidence * 155 + 161L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }

    static int ruleScore145(int severity, int confidence) {
        long v = (long) severity * 152 + (long) confidence * 156 + 162L;
        if (v < 0L) v = -v;
        int r = (int) (v % ScamSafe.Config.SCORE_MAX);
        return normalizeScore(r);
    }
