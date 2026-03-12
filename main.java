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
