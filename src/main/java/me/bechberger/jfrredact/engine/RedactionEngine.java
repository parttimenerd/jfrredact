package me.bechberger.jfrredact.engine;

import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedThread;
import me.bechberger.jfrredact.config.EventConfig;
import me.bechberger.jfrredact.config.RedactionConfig;
import me.bechberger.jfrredact.pseudonimyzer.Pseudonymizer;
import me.bechberger.jfrredact.util.GlobMatcher;
import me.bechberger.jfrredact.util.RegexCache;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Simple redaction engine for JFR events.
 *
 * Main responsibilities:
 * 1. Determine if an event should be removed
 * 2. Redact individual field values based on patterns and configuration
 *
 * Usage:
 * <pre>
 * RedactionEngine engine = new RedactionEngine(config);
 *
 * // Step 1: Check if event should be removed
 * if (engine.shouldRemoveEvent("jdk.OSInformation")) {
 *     // Skip this event
 * }
 *
 * // Step 2: Process each field
 * String redacted = engine.redact("password", "secret123");
 * int redactedPort = engine.redact("port", 8080);
 * </pre>
 */
public class RedactionEngine {

    private static final Logger logger = LoggerFactory.getLogger(RedactionEngine.class);

    private final RedactionConfig config;
    private final Pseudonymizer pseudonymizer;
    private final RedactionStats stats;

    // Compiled patterns cache for performance
    private final Map<String, Pattern> patternCache = new HashMap<>();

    // Ignore lists cache - maps pattern key to IgnoreLists object
    private final Map<String, IgnoreLists> ignoreListCache = new HashMap<>();

    // Discovered patterns from discovery phase (lower priority than configured patterns)
    private DiscoveredPatterns discoveredPatterns = null;

    // Helper class to store all three types of ignore lists
    private static class IgnoreLists {
        final List<String> ignoreExact;
        final List<Pattern> ignorePatterns;
        final List<String> ignoreAfter;

        IgnoreLists(List<String> ignoreExact, List<String> ignoreRegexes, List<String> ignoreAfter) {
            this.ignoreExact = ignoreExact != null ? ignoreExact : List.of();
            this.ignorePatterns = ignoreRegexes != null ?
                ignoreRegexes.stream().map(Pattern::compile).collect(java.util.stream.Collectors.toList()) :
                List.of();
            this.ignoreAfter = ignoreAfter != null ? ignoreAfter : List.of();
        }
    }

    /** No-redaction engine instance for convenience - disables all redactions. */
    public static final RedactionEngine NONE = new RedactionEngine(createDisabledConfig()) {
        @Override
        public boolean shouldRemoveEvent(String eventType) {
            return false;
        }

        @Override
        public boolean shouldRemoveThread(String threadName) {
            return false;
        }

        @Override
        public String redact(String fieldName, String value) {
            return value;
        }

        @Override
        public int redact(String fieldName, int value) {
            return value;
        }

        @Override
        public long redact(String fieldName, long value) {
            return value;
        }

    };

    private static RedactionConfig createDisabledConfig() {
        RedactionConfig config = new RedactionConfig();
        config.getProperties().setEnabled(false);
        config.getEvents().setRemoveEnabled(false);
        config.getStrings().setEnabled(false);
        config.getNetwork().setEnabled(false);
        config.getPaths().setEnabled(false);
        config.getGeneral().getPseudonymization().setEnabled(false);
        return config;
    }

    public RedactionEngine(RedactionConfig config) {
        this(config, new RedactionStats());
    }

    public RedactionEngine(RedactionConfig config, RedactionStats stats) {
        this.config = config;
        this.stats = stats;
        this.pseudonymizer = config.createPseudonymizer();
        compilePatterns();

        logger.debug("RedactionEngine initialized");
        logger.debug("  Properties redaction: {}", config.getProperties().isEnabled());
        logger.debug("  String patterns: {}", config.getStrings().isEnabled());
        logger.debug("  Network redaction: {}", config.getNetwork().isEnabled());
        logger.debug("  Path redaction: {}", config.getPaths().isEnabled());
        logger.debug("  Pseudonymization: {}", config.getGeneral().getPseudonymization().isEnabled());
        logger.debug("  Event removal: {}", config.getEvents().isRemoveEnabled());
    }

    private void compilePatterns() {
        if (!config.getStrings().isEnabled()) {
            return;
        }

        var patterns = config.getStrings().getPatterns();

        // Email patterns
        if (patterns.getEmails().isEnabled()) {
            IgnoreLists emailIgnore = new IgnoreLists(
                patterns.getEmails().getIgnoreExact(),
                patterns.getEmails().getIgnore(),
                patterns.getEmails().getIgnoreAfter()
            );
            for (int i = 0; i < patterns.getEmails().getPatterns().size(); i++) {
                String regex = patterns.getEmails().getPatterns().get(i);
                patternCache.put("email_" + i, Pattern.compile(regex));
                ignoreListCache.put("email_" + i, emailIgnore);
            }
        }

        // IP patterns
        if (patterns.getIpAddresses().isEnabled()) {
            IgnoreLists ipIgnore = new IgnoreLists(
                patterns.getIpAddresses().getIgnoreExact(),
                patterns.getIpAddresses().getIgnore(),
                patterns.getIpAddresses().getIgnoreAfter()
            );
            for (int i = 0; i < patterns.getIpAddresses().getPatterns().size(); i++) {
                String regex = patterns.getIpAddresses().getPatterns().get(i);
                patternCache.put("ip_" + i, Pattern.compile(regex));
                ignoreListCache.put("ip_" + i, ipIgnore);
            }
        }

        // UUID patterns
        if (patterns.getUuids().isEnabled()) {
            IgnoreLists uuidIgnore = new IgnoreLists(
                patterns.getUuids().getIgnoreExact(),
                patterns.getUuids().getIgnore(),
                patterns.getUuids().getIgnoreAfter()
            );
            for (int i = 0; i < patterns.getUuids().getPatterns().size(); i++) {
                String regex = patterns.getUuids().getPatterns().get(i);
                patternCache.put("uuid_" + i, Pattern.compile(regex));
                ignoreListCache.put("uuid_" + i, uuidIgnore);
            }
        }

        // SSH host patterns
        if (patterns.getSshHosts().isEnabled()) {
            IgnoreLists sshIgnore = new IgnoreLists(
                patterns.getSshHosts().getIgnoreExact(),
                patterns.getSshHosts().getIgnore(),
                patterns.getSshHosts().getIgnoreAfter()
            );
            for (int i = 0; i < patterns.getSshHosts().getPatterns().size(); i++) {
                String regex = patterns.getSshHosts().getPatterns().get(i);
                patternCache.put("ssh_" + i, Pattern.compile(regex));
                ignoreListCache.put("ssh_" + i, sshIgnore);
            }
        }

        // User name patterns
        if (patterns.getUser().isEnabled()) {
            IgnoreLists userIgnore = new IgnoreLists(
                patterns.getUser().getIgnoreExact(),
                patterns.getUser().getIgnore(),
                patterns.getUser().getIgnoreAfter()
            );
            for (int i = 0; i < patterns.getUser().getPatterns().size(); i++) {
                String regex = patterns.getUser().getPatterns().get(i);
                patternCache.put("user_" + i, Pattern.compile(regex));
                ignoreListCache.put("user_" + i, userIgnore);
            }
        }

        // Hostname patterns (for hs_err files)
        if (patterns.getHostnames().isEnabled()) {
            for (int i = 0; i < patterns.getHostnames().getPatterns().size(); i++) {
                String regex = patterns.getHostnames().getPatterns().get(i);
                patternCache.put("hostname_" + i, Pattern.compile(regex));
            }
            // Note: hostnames use getIgnoreExact() for safe hostnames
            // handled separately in replaceHostnameMatches
        }

        // Internal URL patterns
        if (patterns.getInternalUrls().isEnabled()) {
            IgnoreLists urlIgnore = new IgnoreLists(
                patterns.getInternalUrls().getIgnoreExact(),
                patterns.getInternalUrls().getIgnore(),
                patterns.getInternalUrls().getIgnoreAfter()
            );
            for (int i = 0; i < patterns.getInternalUrls().getPatterns().size(); i++) {
                String regex = patterns.getInternalUrls().getPatterns().get(i);
                patternCache.put("internal_url_" + i, Pattern.compile(regex));
                ignoreListCache.put("internal_url_" + i, urlIgnore);
            }
        }

        // Custom patterns
        for (int i = 0; i < patterns.getCustom().size(); i++) {
            var customPattern = patterns.getCustom().get(i);
            if (!customPattern.getPatterns().isEmpty()) {
                IgnoreLists customIgnore = new IgnoreLists(
                    customPattern.getIgnoreExact(),
                    customPattern.getIgnore(),
                    customPattern.getIgnoreAfter()
                );
                String baseName = customPattern.getName() != null ? customPattern.getName() : "pattern_" + i;
                for (int j = 0; j < customPattern.getPatterns().size(); j++) {
                    String regex = customPattern.getPatterns().get(j);
                    String key = "custom_" + baseName + (customPattern.getPatterns().size() > 1 ? "_" + j : "");
                    patternCache.put(key, Pattern.compile(regex));
                    ignoreListCache.put(key, customIgnore);
                }
            }
        }
    }

    /**
     * Check if an event should be removed completely.
     *
     * @param eventType The event type name (e.g., "jdk.JavaMonitorEnter")
     * @return true if the event should be removed, false otherwise
     */
    public boolean shouldRemoveEvent(String eventType) {
        return config.getEvents().shouldRemove(eventType);
    }

    /**
     * Check if an event should be removed completely, using jfr scrub-style filtering.
     * Supports filtering by event name, category, and thread name.
     *
     * @param event The recorded event to check
     * @return true if the event should be removed, false otherwise
     */
    public boolean shouldRemoveEvent(RecordedEvent event) {
        // First check simple event type removal
        if (shouldRemoveEvent(event.getEventType().getName())) {
            return true;
        }

        // Then check jfr scrub-style filtering
        EventConfig.FilteringConfig filtering = config.getEvents().getFiltering();
        if (!filtering.hasAnyFilters()) {
            return false; // No filters configured
        }

        String eventName = event.getEventType().getName();
        List<String> categories = event.getEventType().getCategoryNames();
        String threadName = getThreadName(event);

        // Check thread filtering first using the dedicated method
        if (shouldRemoveThread(threadName)) {
            logger.debug("Removing event (thread filtered): {} ({})", eventName, threadName);
            return true;
        }

        String sampledThreadName = getSampledThreadName(event);
        if (shouldRemoveThread(sampledThreadName)) {
            logger.debug("Removing event (sampled thread filtered): {} ({})", eventName, sampledThreadName);
            return true;
        }

        // Apply filters in order: include, then exclude
        // If any include filter is specified, event must match at least one to be kept
        // Note: Thread includes are handled separately above, so we don't count them here

        boolean hasIncludeFilters = !filtering.getIncludeEvents().isEmpty() ||
                                   !filtering.getIncludeCategories().isEmpty();

        if (hasIncludeFilters) {
            boolean included = false;

            // Check event name includes
            if (!filtering.getIncludeEvents().isEmpty()) {
                if (GlobMatcher.matches(eventName, filtering.getIncludeEvents())) {
                    included = true;
                }
            }

            // Check category includes
            if (!included && !filtering.getIncludeCategories().isEmpty()) {
                for (String category : categories) {
                    if (GlobMatcher.matches(category, filtering.getIncludeCategories())) {
                        included = true;
                        break;
                    }
                }
            }


            if (!included) {
                logger.debug("Removing event (not included): {}", eventName);
                return true; // Event doesn't match any include filter
            }
        }

        // Check exclude filters
        if (!filtering.getExcludeEvents().isEmpty()) {
            if (GlobMatcher.matches(eventName, filtering.getExcludeEvents())) {
                logger.debug("Removing event (excluded by event name): {}", eventName);
                return true;
            }
        }

        if (!filtering.getExcludeCategories().isEmpty()) {
            for (String category : categories) {
                if (GlobMatcher.matches(category, filtering.getExcludeCategories())) {
                    logger.debug("Removing event (excluded by category): {} ({})", eventName, category);
                    return true;
                }
            }
        }

        // Note: Thread excludes are now handled by shouldFilterThread() above

        return false; // Event passes all filters
    }

    /**
     * Extract thread name from event, handling null safely.
     */
    private @Nullable String getThreadName(RecordedEvent event) {
        try {
            RecordedThread thread = event.getThread();
            return thread != null ? thread.getJavaName() : null;
        } catch (Exception e) {
            // Some events might not have a thread field
            return null;
        }
    }

    private @Nullable String getSampledThreadName(RecordedEvent event) {
        try {
            RecordedThread thread = event.getThread("sampledThread");
            return thread != null ? thread.getJavaName() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Check if events from a given thread should be filtered out.
     *
     * @param threadName The thread name to check
     * @return true if events from this thread should be filtered out (removed), false otherwise
     */
    public boolean shouldRemoveThread(String threadName) {
        if (threadName == null) {
            return false;
        }

        EventConfig.FilteringConfig filtering = config.getEvents().getFiltering();
        if (!filtering.hasAnyFilters()) {
            return false; // No filters configured
        }

        // If include filters are specified, thread must match at least one to be kept
        if (!filtering.getIncludeThreads().isEmpty()) {
            if (!GlobMatcher.matches(threadName, filtering.getIncludeThreads())) {
                // Thread doesn't match any include filter - should be filtered
                return true;
            }
        }

        // Check exclude filters
        if (!filtering.getExcludeThreads().isEmpty()) {
            // Thread matches exclude filter - should be filtered
            return GlobMatcher.matches(threadName, filtering.getExcludeThreads());
        }

        return false; // Thread should not be filtered
    }

    // ========== Redaction methods for all supported types ==========

    /**
     * Redact a String value.
     * Auto-detects if it's a property, email, IP, path, etc.
     */
    public String redact(String fieldName, String value) {
        if (value == null) {
            return null;
        }

        // 1. Check if field name matches property patterns
        if (config.getProperties().isEnabled() &&
            config.getProperties().matches(fieldName)) {
            String redacted = applyRedaction(value, "property");
            logger.debug("Redacted property '{}': '{}' -> '{}'", fieldName, truncateForLog(value), truncateForLog(redacted));
            stats.recordRedactedField(fieldName);
            stats.recordRedactionType("property");
            return redacted;
        }

        // 2. Check string patterns (email, IP, UUID, etc.)
        if (config.getStrings().isEnabled()) {
            RedactionResult result = checkStringPatternsWithType(value);
            if (result.wasRedacted()) {
                logger.debug("Redacted {} in '{}': '{}' -> '{}'",
                    result.getRedactionType(), fieldName,
                    truncateForLog(value), truncateForLog(result.getRedactedValue()));
                stats.recordRedactedField(fieldName);
                stats.recordRedactionType(result.getRedactionType());
                return result.getRedactedValue();
            }
        }

        // 3. No redaction needed
        return value;
    }

    /**
     * Truncate a value for logging to avoid excessively long log lines.
     */
    private String truncateForLog(String value) {
        if (value == null) return "null";
        if (value.length() <= 100) return value;
        return value.substring(0, 97) + "...";
    }

    /**
     * Result of a redaction operation, including the type of redaction applied.
     */
    private static class RedactionResult {
        private final String redactedValue;
        private final String redactionType;
        private final boolean wasRedacted;

        RedactionResult(String redactedValue, String redactionType, boolean wasRedacted) {
            this.redactedValue = redactedValue;
            this.redactionType = redactionType;
            this.wasRedacted = wasRedacted;
        }

        static RedactionResult noChange(String value) {
            return new RedactionResult(value, null, false);
        }

        static RedactionResult redacted(String value, String type) {
            return new RedactionResult(value, type, true);
        }

        String getRedactedValue() { return redactedValue; }
        String getRedactionType() { return redactionType; }
        boolean wasRedacted() { return wasRedacted; }
    }

    /**
     * Redact an int value (e.g., port numbers).
     */
    public int redact(String fieldName, int value) {
        if (isPortField(fieldName)) {
            int redacted = pseudonymizer.pseudonymizePort(value);
            if (redacted != value) {
                logger.debug("Redacted port '{}': {} -> {}", fieldName, value, redacted);
                stats.recordRedactedField(fieldName);
                stats.recordRedactionType("port");
            }
            return redacted;
        }
        return value;
    }

    /**
     * Redact a long value (e.g., port numbers).
     */
    public long redact(String fieldName, long value) {
        if (isPortField(fieldName)) {
            return pseudonymizer.pseudonymizePort((int) value);
        }
        return value;
    }

    /**
     * Redact a boolean value (pass-through, no redaction).
     */
    public boolean redact(String fieldName, boolean value) {
        return value;
    }

    /**
     * Redact a byte value (pass-through, no redaction).
     */
    public byte redact(String fieldName, byte value) {
        return value;
    }

    /**
     * Redact a char value (pass-through, no redaction).
     */
    public char redact(String fieldName, char value) {
        return value;
    }

    /**
     * Redact a short value (pass-through, no redaction).
     */
    public short redact(String fieldName, short value) {
        return value;
    }

    /**
     * Redact a float value (pass-through, no redaction).
     */
    public float redact(String fieldName, float value) {
        return value;
    }

    /**
     * Redact a double value (pass-through, no redaction).
     */
    public double redact(String fieldName, double value) {
        return value;
    }

    // ========== Helper methods ==========

    private boolean isPortField(String fieldName) {
        if (fieldName == null) return false;
        String lower = fieldName.toLowerCase();
        return lower.contains("port") ||
               lower.equals("p") ||
               lower.equals("sourceport") ||
               lower.equals("destinationport");
    }

    /**
     * Check string patterns and return the redaction result with type information.
     */
    private RedactionResult checkStringPatternsWithType(String value) {
        String result = value;
        String redactionType = null;

        // Check email patterns - use find() for partial matching
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("email_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, entry.getKey());
                    if (redactionType == null) redactionType = "email";
                }
            }
        }

        // Check IP patterns - use find() for partial matching
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("ip_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, entry.getKey());
                    if (redactionType == null) redactionType = "ip";
                }
            }
        }

        // Check UUID patterns - use find() for partial matching
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("uuid_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, entry.getKey());
                    if (redactionType == null) redactionType = "uuid";
                }
            }
        }

        // Check SSH host patterns
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("ssh_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, "ssh_host");
                    if (redactionType == null) redactionType = "ssh_host";
                }
            }
        }

        // Check user/home directory patterns - replaces only the captured username, not the entire path
        // This preserves the path structure (e.g., /Users/***/ instead of ***)
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("user_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceCaptureGroup(matcher, result, 1, "home_directory");
                    if (redactionType == null) redactionType = "home_directory";
                }
            }
        }

        // Check internal URL patterns BEFORE hostnames (URLs may contain hostnames)
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("internal_url_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, "internal_url");
                    if (redactionType == null) redactionType = "internal_url";
                }
            }
        }

        // Check hostname patterns (with safe hostname filtering)
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("hostname_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    String before = result;
                    result = replaceHostnameMatches(matcher, result);
                    if (!result.equals(before) && redactionType == null) redactionType = "hostname";
                }
            }
        }

        // Check custom patterns (including CLI-added patterns)
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("custom_") || key.startsWith("cli_pattern_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, key);
                    if (redactionType == null) redactionType = key.startsWith("cli_") ? "custom_cli" : "custom";
                }
            }
        }

        // Check discovered patterns (lower priority - only if not already redacted by configured patterns)
        if (discoveredPatterns != null && !result.equals(value)) {
            // Only apply discovered patterns if we haven't already redacted
        } else if (discoveredPatterns != null) {
            String discoveryResult = applyDiscoveredPatterns(result);
            if (!discoveryResult.equals(result)) {
                result = discoveryResult;
                if (redactionType == null) redactionType = "discovered";
            }
        }

        if (!result.equals(value)) {
            return RedactionResult.redacted(result, redactionType != null ? redactionType : "pattern");
        }
        return RedactionResult.noChange(value);
    }

    private String checkStringPatterns(String value) {
        String result = value;

        // Check email patterns - use find() for partial matching
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("email_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, entry.getKey());
                }
            }
        }

        // Check IP patterns - use find() for partial matching
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("ip_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, entry.getKey());
                }
            }
        }

        // Check UUID patterns - use find() for partial matching
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("uuid_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, entry.getKey());
                }
            }
        }

        // Check SSH host patterns
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("ssh_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, "ssh_host");
                }
            }
        }

        // Check user/home directory patterns - replaces only the captured username, not the entire path
        // This preserves the path structure (e.g., /Users/***/ instead of ***)
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("user_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceCaptureGroup(matcher, result, 1, "home_directory");
                }
            }
        }

        // Check internal URL patterns BEFORE hostnames (URLs may contain hostnames)
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("internal_url_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, "internal_url");
                }
            }
        }

        // Check hostname patterns (with safe hostname filtering)
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            if (entry.getKey().startsWith("hostname_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceHostnameMatches(matcher, result);
                }
            }
        }

        // Check custom patterns (including CLI-added patterns)
        for (Map.Entry<String, Pattern> entry : patternCache.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("custom_") || key.startsWith("cli_pattern_")) {
                Matcher matcher = entry.getValue().matcher(result);
                if (matcher.find()) {
                    result = replaceMatches(matcher, result, key);
                }
            }
        }

        return result;
    }

    private String replaceMatches(Matcher matcher, String value, String patternKey) {
        // Reset matcher to scan from beginning
        matcher.reset();

        // Get global no_redact list
        List<String> noRedact = config.getStrings().getNoRedact();

        // Get pattern-specific ignore lists
        IgnoreLists ignoreLists = ignoreListCache.getOrDefault(patternKey, new IgnoreLists(null, null, null));

        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String matched = matcher.group();
            int matchStart = matcher.start();

            // Check if this string should not be redacted
            boolean shouldNotRedact = false;

            // 1. Check global no_redact list
            for (String safe : noRedact) {
                if (matched.contains(safe)) {
                    shouldNotRedact = true;
                    break;
                }
            }

            // 2. Check pattern-specific ignore_exact
            if (!shouldNotRedact) {
                for (String exact : ignoreLists.ignoreExact) {
                    if (matched.equalsIgnoreCase(exact)) {
                        shouldNotRedact = true;
                        break;
                    }
                }
            }

            // 3. Check pattern-specific ignore (regex patterns)
            if (!shouldNotRedact) {
                for (Pattern ignorePattern : ignoreLists.ignorePatterns) {
                    if (ignorePattern.matcher(matched).matches()) {
                        shouldNotRedact = true;
                        break;
                    }
                }
            }

            // 4. Check pattern-specific ignore_after (prefix before the match)
            if (!shouldNotRedact && matchStart > 0) {
                for (String prefix : ignoreLists.ignoreAfter) {
                    // Check if the text before the match ends with this prefix
                    String before = value.substring(Math.max(0, matchStart - prefix.length()), matchStart);
                    if (before.equals(prefix) || before.matches(prefix)) {
                        shouldNotRedact = true;
                        break;
                    }
                }
            }

            if (shouldNotRedact) {
                // Don't redact - keep original
                matcher.appendReplacement(sb, Matcher.quoteReplacement(matched));
            } else if (pseudonymizer.isEnabled()) {
                // With pseudonymization, each unique match gets its own pseudonym
                String replacement = pseudonymizer.pseudonymize(matched, config.getGeneral().getRedactionText());
                matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            } else {
                // Simple redaction
                matcher.appendReplacement(sb, Matcher.quoteReplacement(config.getGeneral().getRedactionText()));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private String replaceHostnameMatches(Matcher matcher, String value) {
        // Reset matcher to scan from beginning
        matcher.reset();

        // Get safe hostnames list (using ignore_exact)
        List<String> safeHostnames = config.getStrings().getPatterns().getHostnames().getIgnoreExact();

        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String matched = matcher.group();

            // Check if this is a safe hostname
            boolean isSafe = false;
            for (String safe : safeHostnames) {
                if (matched.equalsIgnoreCase(safe)) {
                    isSafe = true;
                    break;
                }
            }

            if (isSafe) {
                // Don't redact safe hostnames - keep original
                matcher.appendReplacement(sb, Matcher.quoteReplacement(matched));
            } else {
                // Redact this hostname
                String replacement = pseudonymizer.isEnabled()
                    ? pseudonymizer.pseudonymize(matched, config.getGeneral().getRedactionText())
                    : config.getGeneral().getRedactionText();
                matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private String replaceSafeIpMatches(Matcher matcher, String value) {
        // Reset matcher to scan from beginning
        matcher.reset();

        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String matched = matcher.group();

            // Check if this is localhost/loopback IP
            boolean isSafe = matched.equals("127.0.0.1") || matched.startsWith("127.") ||
                            matched.equals("::1");

            if (isSafe) {
                // Don't redact safe IPs - keep original
                matcher.appendReplacement(sb, Matcher.quoteReplacement(matched));
            } else {
                // Redact this IP
                String replacement = pseudonymizer.isEnabled()
                    ? pseudonymizer.pseudonymize(matched, config.getGeneral().getRedactionText())
                    : config.getGeneral().getRedactionText();
                matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * Replace only a specific capture group in matches, preserving the rest of the match.
     * This is used for patterns like /Users/([^/]+) where we want to redact only the username,
     * not the entire path structure.
     */
    private String replaceCaptureGroup(Matcher matcher, String value, int groupNum, String patternKey) {
        // Reset matcher to scan from beginning
        matcher.reset();

        StringBuilder sb = new StringBuilder();
        int lastEnd = 0;

        while (matcher.find()) {
            // Check if the capture group exists
            if (matcher.groupCount() < groupNum) {
                continue;
            }

            String capturedValue = matcher.group(groupNum);
            if (capturedValue == null || capturedValue.isEmpty()) {
                continue;
            }

            // Get the redaction replacement
            String replacement = pseudonymizer.isEnabled()
                ? pseudonymizer.pseudonymize(capturedValue, config.getGeneral().getRedactionText())
                : config.getGeneral().getRedactionText();

            // Append text before this match
            sb.append(value, lastEnd, matcher.start());

            // Build the replacement keeping the parts before and after the capture group
            String fullMatch = matcher.group();
            int groupStartInMatch = matcher.start(groupNum) - matcher.start();
            int groupEndInMatch = matcher.end(groupNum) - matcher.start();

            sb.append(fullMatch, 0, groupStartInMatch);
            sb.append(replacement);
            sb.append(fullMatch, groupEndInMatch, fullMatch.length());

            lastEnd = matcher.end();
        }

        // Append remaining text
        sb.append(value, lastEnd, value.length());
        return sb.toString();
    }

    private String applyRedaction(String value, String context) {
        // Use pseudonymization if enabled
        if (pseudonymizer.isEnabled()) {
            return pseudonymizer.pseudonymize(value, config.getGeneral().getRedactionText());
        }

        // Otherwise use simple redaction
        return config.getGeneral().getRedactionText();
    }

    /**
     * Get the pseudonymizer instance (for accessing statistics, clearing cache, etc.)
     */
    public Pseudonymizer getPseudonymizer() {
        return pseudonymizer;
    }

    /**
     * Get the statistics tracker.
     */
    public RedactionStats getStats() {
        return stats;
    }

    /**
     * Get the configuration used by this redaction engine.
     */
    public RedactionConfig getConfig() {
        return config;
    }

    // ========== Discovered Patterns Support ==========

    /**
     * Set discovered patterns to be used for redaction.
     * Discovered patterns have lower priority than configured patterns.
     *
     * @param patterns The discovered patterns from the discovery phase (already filtered by min_occurrences)
     */
    public void setDiscoveredPatterns(DiscoveredPatterns patterns) {
        this.discoveredPatterns = patterns;
        if (patterns != null) {
            int count = patterns.getTotalCount();
            logger.info("Loaded {} discovered patterns for redaction", count);
        }
    }

    /**
     * Get the currently set discovered patterns.
     */
    public DiscoveredPatterns getDiscoveredPatterns() {
        return discoveredPatterns;
    }

    /**
     * Apply discovered patterns to a string value.
     * Only redacts values that were discovered in the discovery phase.
     * The patterns are already filtered by their individual min_occurrences thresholds.
     */
    private String applyDiscoveredPatterns(String value) {
        if (discoveredPatterns == null || value == null || value.isEmpty()) {
            return value;
        }

        List<DiscoveredPatterns.DiscoveredValue> values = discoveredPatterns.getValues(1);

        if (values.isEmpty()) {
            return value;
        }

        String result = value;
        boolean caseSensitive = discoveredPatterns.isCaseSensitive();

        // Sort by value length (longest first) to avoid partial replacements
        values.sort((a, b) -> Integer.compare(b.getValue().length(), a.getValue().length()));

        int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;

        for (DiscoveredPatterns.DiscoveredValue discovered : values) {
            String toFind = discovered.getValue();

            boolean found = caseSensitive
                ? result.contains(toFind)
                : result.toLowerCase().contains(toFind.toLowerCase());

            if (found) {
                // Replace all occurrences
                String replacement = pseudonymizer.isEnabled()
                    ? pseudonymizer.pseudonymize(toFind, config.getGeneral().getRedactionText())
                    : config.getGeneral().getRedactionText();

                // Use case-sensitive or case-insensitive replacement
                if (caseSensitive) {
                    result = result.replace(toFind, replacement);
                } else {
                    // Case-insensitive replacement - need to find and replace all occurrences
                    result = replaceCaseInsensitive(result, toFind, replacement);
                }

                logger.trace("Redacted discovered {} value '{}' in text",
                           discovered.getType(), toFind);
            }
        }

        return result;
    }

    /**
     * Replace all occurrences of toFind in text with replacement, case-insensitively.
     */
    private String replaceCaseInsensitive(String text, String toFind, String replacement) {
        if (toFind.isEmpty()) return text;

        String lowerText = text.toLowerCase();
        String lowerToFind = toFind.toLowerCase();
        StringBuilder result = new StringBuilder();
        int lastIndex = 0;
        int index;

        while ((index = lowerText.indexOf(lowerToFind, lastIndex)) != -1) {
            result.append(text, lastIndex, index);
            result.append(replacement);
            lastIndex = index + toFind.length();
        }
        result.append(text.substring(lastIndex));

        return result.toString();
    }
}