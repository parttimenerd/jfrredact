package me.bechberger.jfrredact.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Thread-safe cache for compiled regular expressions.
 * Provides automatic caching to avoid recompiling the same patterns repeatedly.
 *
 * Usage:
 * <pre>
 * RegexCache cache = new RegexCache();
 * if (cache.matches("\\d+", input)) { ... }
 * Matcher m = cache.matcher("\\d+", input);
 * </pre>
 */
public class RegexCache {

    private final ConcurrentHashMap<CacheKey, Pattern> cache = new ConcurrentHashMap<>();

    /**
     * Cache key combining pattern string and flags.
     */
    private static class CacheKey {
        private final String pattern;
        private final int flags;

        CacheKey(String pattern, int flags) {
            this.pattern = pattern;
            this.flags = flags;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CacheKey cacheKey = (CacheKey) o;
            return flags == cacheKey.flags && pattern.equals(cacheKey.pattern);
        }

        @Override
        public int hashCode() {
            return 31 * pattern.hashCode() + flags;
        }
    }

    /**
     * Get or compile a pattern with no flags.
     */
    public Pattern getPattern(String regex) {
        return getPattern(regex, 0);
    }

    /**
     * Get or compile a pattern with specified flags.
     */
    public Pattern getPattern(String regex, int flags) {
        CacheKey key = new CacheKey(regex, flags);
        return cache.computeIfAbsent(key, k -> Pattern.compile(regex, flags));
    }
}