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
