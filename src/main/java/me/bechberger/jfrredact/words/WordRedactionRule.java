package me.bechberger.jfrredact.words;
import java.util.regex.Pattern;

public class WordRedactionRule {
    public enum RuleType {
        REDACT, KEEP, REPLACE, REDACT_PREFIX
    }

    private final RuleType type;
    private final String pattern;
    private final String replacement;
    private final boolean isRegex;
    private final Pattern compiledPattern; // Cache compiled pattern

    public WordRedactionRule(RuleType type, String pattern, String replacement, boolean isRegex) {
        this.type = type;
        this.pattern = pattern;
        this.replacement = replacement;
        this.isRegex = isRegex;
        // Compile pattern once during construction if it's a regex
        this.compiledPattern = isRegex ? Pattern.compile(pattern) : null;
    }

    public static WordRedactionRule redact(String pattern, boolean isRegex) {
        return new WordRedactionRule(RuleType.REDACT, pattern, null, isRegex);
    }

    public static WordRedactionRule keep(String pattern, boolean isRegex) {
        return new WordRedactionRule(RuleType.KEEP, pattern, null, isRegex);
    }

    public static WordRedactionRule replace(String pattern, String replacement, boolean isRegex) {
        return new WordRedactionRule(RuleType.REPLACE, pattern, replacement, isRegex);
    }

    public static WordRedactionRule redactPrefix(String prefix) {
        return new WordRedactionRule(RuleType.REDACT_PREFIX, prefix, null, false);
    }

    public RuleType getType() { return type; }
    public String getPattern() { return pattern; }
    public String getReplacement() { return replacement; }
    public boolean isRegex() { return isRegex; }

    public boolean matches(String word) {
        if (isRegex) {
            // Use cached compiled pattern
            return compiledPattern.matcher(word).matches();
        } else if (type == RuleType.REDACT_PREFIX) {
            return word.startsWith(pattern);
        } else {
            return word.equals(pattern);
        }
    }
    public static WordRedactionRule parse(String line) {
        line = line.trim();
        if (line.startsWith("-$")) {
            String prefix = line.substring(2).trim();
            return redactPrefix(prefix);
        } else if (line.startsWith("-")) {
            String pattern = line.substring(1).trim();
            boolean isRegex = pattern.startsWith("/") && pattern.endsWith("/");
            if (isRegex) {
                pattern = pattern.substring(1, pattern.length() - 1);
            }
            return redact(pattern, isRegex);
        } else if (line.startsWith("+")) {
            String pattern = line.substring(1).trim();
            boolean isRegex = pattern.startsWith("/") && pattern.endsWith("/");
            if (isRegex) {
                pattern = pattern.substring(1, pattern.length() - 1);
            }
            return keep(pattern, isRegex);
        } else if (line.startsWith("!")) {
            String rest = line.substring(1).trim();
            int spaceIdx = rest.indexOf(' ');
            if (spaceIdx < 0) {
                throw new IllegalArgumentException("Replace rule must have format: ! pattern replacement");
            }
            String pattern = rest.substring(0, spaceIdx).trim();
            String replacement = rest.substring(spaceIdx + 1).trim();
            boolean isRegex = pattern.startsWith("/") && pattern.endsWith("/");
            if (isRegex) {
                pattern = pattern.substring(1, pattern.length() - 1);
            }
            return replace(pattern, replacement, isRegex);
        } else {
            // Unknown line format - return null to ignore
            return null;
        }
    }
    public String format() {
        String patternStr = isRegex ? "/" + pattern + "/" : pattern;
        if (type == RuleType.REDACT) {
            return "- " + patternStr;
        } else if (type == RuleType.KEEP) {
            return "+ " + patternStr;
        } else if (type == RuleType.REPLACE) {
            return "! " + patternStr + " " + replacement;
        } else {
            return "-$ " + pattern;
        }
    }
    public String toString() {
        return format();
    }
}