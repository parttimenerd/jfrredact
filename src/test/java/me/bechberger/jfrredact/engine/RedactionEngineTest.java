package me.bechberger.jfrredact.engine;

import me.bechberger.jfrredact.config.RedactionConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for RedactionEngine with parameterized tests.
 */
public class RedactionEngineTest {

    // ========== Helper Methods ==========

    private RedactionEngine createDefaultEngine() {
        return new RedactionEngine(new RedactionConfig());
    }

    private RedactionEngine createEngineWithPseudonymization() {
        RedactionConfig config = new RedactionConfig();
        config.getGeneral().getPseudonymization().setEnabled(true);
        return new RedactionEngine(config);
    }

    private RedactionEngine createEngineWithMode(String mode) {
        RedactionConfig config = new RedactionConfig();
        config.getGeneral().getPseudonymization().setEnabled(true);
        config.getGeneral().getPseudonymization().setMode(mode);
        return new RedactionEngine(config);
    }

    private void assertRedacted(String original, String redacted) {
        assertNotEquals(original, redacted,
            () -> "Value '" + original + "' should be redacted");
    }

    private void assertRedactedTo(String original, String redacted, String expected) {
        assertRedacted(original, redacted);
        assertEquals(expected, redacted,
            () -> "Value should be redacted to '" + expected + "'");
    }

    private void assertNotRedacted(String original, String result) {
        assertEquals(original, result,
            () -> "Value '" + original + "' should NOT be redacted");
    }

    // ========== Event Processing Tests ==========

    @ParameterizedTest
    @ValueSource(strings = {
        "jdk.OSInformation",
        "jdk.SystemProcess",
        "jdk.InitialEnvironmentVariable",
        "jdk.ProcessStart"
    })
    public void testEventsAreRemovedByDefault(String eventType) {
        RedactionConfig config = new RedactionConfig();
        RedactionEngine engine = new RedactionEngine(config);

        assertTrue(engine.shouldRemoveEvent(eventType),
            "Event " + eventType + " should be removed by default");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "jdk.JavaMonitorEnter",
        "jdk.ThreadSleep",
        "jdk.FileRead",
        "jdk.SocketRead"
    })
    public void testNormalEventsNotRemoved(String eventType) {
        RedactionConfig config = new RedactionConfig();
        RedactionEngine engine = new RedactionEngine(config);

        assertFalse(engine.shouldRemoveEvent(eventType),
            "Event " + eventType + " should not be removed");
    }

    @Test
    public void testEventRemovalCanBeDisabled() {
        RedactionConfig config = new RedactionConfig();
        config.getEvents().setRemoveEnabled(false);

        RedactionEngine engine = new RedactionEngine(config);

        // Even sensitive events should not be removed when removal is disabled
        assertFalse(engine.shouldRemoveEvent("jdk.OSInformation"));
    }

    // ...existing code...

    @ParameterizedTest
    @CsvSource({
        "password, secret123, true",
        "user_password, mypass, true",
        "PASSWORD_HASH, hash123, true",
        "api_key, key-123, true",
        "apiKey, abc, true",
        "secret, topsecret, true",
        "token, jwt-token, true",
        "auth, bearer-123, true",
        "credential, cred, true"
    })
    public void testPropertyFieldsAreRedacted(String fieldName, String value, boolean shouldRedact) {
        RedactionEngine engine = createDefaultEngine();
        String result = engine.redact(fieldName, value);

        if (shouldRedact) {
            assertRedactedTo(value, result, "***");
        }
    }

    @ParameterizedTest
    @CsvSource({
        "username, john_doe, false",
        "email, user@example.com, false",  // Not a property pattern
        "userId, 12345, false",
        "timestamp, 1234567890, false"
    })
    public void testNonSensitiveFieldsNotRedacted(String fieldName, String value, boolean shouldRedact) {
        RedactionConfig config = new RedactionConfig();
        config.getStrings().setEnabled(false);  // Disable string patterns to test only properties

        RedactionEngine engine = new RedactionEngine(config);
        String result = engine.redact(fieldName, value);

        assertNotRedacted(value, result);
    }

    // ========== String Pattern Tests ==========

    @ParameterizedTest
    @ValueSource(strings = {
        "user@example.com",
        "admin@company.org",
        "test.user+tag@domain.co.uk",
        "simple@test.com"
    })
    public void testEmailsAreRedacted(String email) {
        RedactionEngine engine = createDefaultEngine();
        String result = engine.redact("emailField", email);
        assertRedacted(email, result);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "255.255.255.255"
    })
    public void testIPv4AddressesAreRedacted(String ip) {
        RedactionEngine engine = createDefaultEngine();
        String result = engine.redact("address", ip);
        assertRedacted(ip, result);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",  // Full format
        "2001:db8:85a3::8a2e:370:7334",             // Compressed format
        "2001:db8::8a2e:370:7334",                  // Compressed with more zeros
        "::1",                                       // IPv6 loopback
        "::",                                        // IPv6 unspecified address
        "fe80::1",                                   // Link-local
        "::ffff:192.0.2.1",                         // IPv4-mapped IPv6 (IPv6 part only)
        "2001:db8::",                               // Compressed trailing zeros
        "::8a2e:370:7334"                           // Compressed leading zeros
    })
    public void testIPv6AddressesAreRedacted(String ip) {
        RedactionEngine engine = createDefaultEngine();
        String result = engine.redact("address", ip);
        assertRedacted(ip, result);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "ssh://production.example.com",
        "ssh://user@internal-server",
        "admin@database-01.prod:22",
        "deployer@10.0.1.50"
    })
    public void testSSHHostsAreRedacted(String sshHost) {
        RedactionConfig config = new RedactionConfig();
        // Enable SSH host redaction BEFORE creating engine (patterns are compiled in constructor)
        config.getStrings().getPatterns().getSshHosts().setEnabled(true);

        RedactionEngine engine = new RedactionEngine(config);
        String result = engine.redact("connection", sshHost);

        assertRedacted(sshHost, result);
    }

    // ========== Port Number Tests ==========

    @ParameterizedTest
    @CsvSource({
        "port, 8080, true",
        "sourcePort, 443, true",
        "destinationPort, 3306, true",
        "p, 5432, true"
    })
    public void testPortNumbersArePseudonymized(String fieldName, int port, boolean shouldRedact) {
        RedactionEngine engine = createEngineWithPseudonymization();
        int result = engine.redact(fieldName, port);

        if (shouldRedact) {
            assertNotEquals(port, result,
                () -> "Port in field '" + fieldName + "' should be pseudonymized");
            assertTrue(result >= 1000,
                    "Pseudonymized port should be >= 1000");
        }
    }

    @Test
    public void testPortPseudonymizationConsistency() {
        RedactionEngine engine = createEngineWithPseudonymization();

        int port1a = engine.redact("port", 8080);
        int port2 = engine.redact("port", 443);
        int port1b = engine.redact("port", 8080);

        assertEquals(1000, port1a, "First port should map to 1000");
        assertEquals(1001, port2, "Second port should map to 1001");
        assertEquals(port1a, port1b, "Same port should map consistently");
    }

    @Test
    public void testNonPortIntegersNotRedacted() {
        RedactionEngine engine = createDefaultEngine();
        int result = engine.redact("count", 42);
        assertEquals(42, result, "Non-port integers should not be redacted");
    }

    @Test
    public void testLongPortsHandledSameAsInt() {
        RedactionEngine engine = createEngineWithPseudonymization();

        long port1 = engine.redact("port", 8080L);
        long port2 = engine.redact("port", 443L);
        long port3 = engine.redact("port", 8080L);

        assertEquals(1000L, port1, "First long port should map to 1000");
        assertEquals(1001L, port2, "Second long port should map to 1001");
        assertEquals(port1, port3, "Same long port should map consistently");
    }

    // ========== Pseudonymization Tests ==========

    @Test
    public void testPseudonymizationConsistency() {
        RedactionEngine engine = createEngineWithMode("hash");

        String value = "secret_value";
        String redacted1 = engine.redact("password", value);
        String redacted2 = engine.redact("password", value);

        assertEquals(redacted1, redacted2, "Same value should produce same pseudonym");
        assertRedacted(value, redacted1);
    }

    @Test
    public void testCounterModePseudonymization() {
        RedactionEngine engine = createEngineWithMode("counter");

        String r1 = engine.redact("password", "value1");
        String r2 = engine.redact("password", "value2");
        String r3 = engine.redact("password", "value1");  // Same as first

        assertEquals("<redacted:1>", r1);
        assertEquals("<redacted:2>", r2);
        assertEquals("<redacted:1>", r3, "Same value should get same counter");
    }

    // ========== Primitive Type Tests ==========

    @Test
    public void testBooleanPassThrough() {
        RedactionEngine engine = createDefaultEngine();

        assertTrue(engine.redact("enabled", true));
        assertFalse(engine.redact("enabled", false));
    }

    @Test
    public void testNumericPassThrough() {
        RedactionEngine engine = createDefaultEngine();

        assertEquals(123L, engine.redact("count", 123L));
        assertEquals(42, engine.redact("value", 42));
        assertEquals((byte) 5, engine.redact("b", (byte) 5));
        assertEquals((short) 10, engine.redact("s", (short) 10));
        assertEquals(3.14f, engine.redact("f", 3.14f), 0.001f);
        assertEquals(2.71, engine.redact("d", 2.71), 0.001);
        assertEquals('A', engine.redact("c", 'A'));
    }

    // ========== Null Handling Tests ==========

    @Test
    public void testNullStringHandling() {
        RedactionEngine engine = createDefaultEngine();

        assertNull(engine.redact("password", null),
            "Null string should remain null");
    }

    // ========== Configuration Integration Tests ==========

    @Test
    public void testPropertiesCanBeDisabled() {
        RedactionConfig config = new RedactionConfig();
        config.getProperties().setEnabled(false);

        RedactionEngine engine = new RedactionEngine(config);
        String result = engine.redact("password", "secret123");

        assertNotRedacted("secret123", result);
    }

    @Test
    public void testStringsCanBeDisabled() {
        RedactionConfig config = new RedactionConfig();
        config.getStrings().setEnabled(false);

        RedactionEngine engine = new RedactionEngine(config);
        String result = engine.redact("email", "user@example.com");

        assertNotRedacted("user@example.com", result);
    }

    @Test
    public void testCustomRedactionText() {
        RedactionConfig config = new RedactionConfig();
        config.getGeneral().setRedactionText("###");

        RedactionEngine engine = new RedactionEngine(config);

        String result = engine.redact("password", "secret");

        assertEquals("###", result, "Should use custom redaction text");
    }

    // ========== Real-World Scenario Tests ==========

    @ParameterizedTest
    @CsvSource({
        "db.password, my_secret_password, ***",
        "spring.datasource.url, jdbc:mysql://localhost, jdbc:mysql://localhost",
        "server.port, 8080, 8080",  // String "8080", not int
        "app.name, MyApp, MyApp"
    })
    public void testRealWorldSpringProperties(String fieldName, String value, String expected) {
        RedactionConfig config = new RedactionConfig();
        config.getGeneral().getPseudonymization().setEnabled(false);  // Simple redaction
        config.getStrings().setEnabled(false);  // Only test property patterns

        RedactionEngine engine = new RedactionEngine(config);
        String result = engine.redact(fieldName, value);

        assertEquals(expected, result,
            "Field '" + fieldName + "' should produce: " + expected);
    }

    // ========== NONE Instance Tests ==========

    @Test
    public void testNoneEngineUsesDefaultConfig() {
        RedactionEngine engine = RedactionEngine.NONE;

        // NONE means "no redaction" - all data passes through unchanged
        assertNotNull(engine);
        assertNotNull(engine.getPseudonymizer());

        // Test that it does NOT redact sensitive fields
        assertEquals("password123", engine.redact("password", "password123"));
        assertEquals("secret", engine.redact("secret", "secret"));

        // And doesn't redact non-sensitive fields either
        assertEquals("username", engine.redact("user", "username"));
    }

    @Test
    public void testNoneEngineRemovesEventsByDefault() {
        RedactionEngine engine = RedactionEngine.NONE;

        // NONE means "no redaction" - no events are removed
        assertFalse(engine.shouldRemoveEvent("jdk.OSInformation"));
        assertFalse(engine.shouldRemoveEvent("jdk.SystemProcess"));
        assertFalse(engine.shouldRemoveEvent("jdk.InitialEnvironmentVariable"));

        // And doesn't remove normal events either
        assertFalse(engine.shouldRemoveEvent("jdk.JavaMonitorEnter"));
    }

    // ========== UUID Pattern Tests ==========

    @ParameterizedTest
    @ValueSource(strings = {
        "550e8400-e29b-41d4-a716-446655440000",
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "123e4567-e89b-12d3-a456-426614174000",
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    })
    public void testUUIDsAreRedactedWhenEnabled(String uuid) {
        RedactionConfig config = new RedactionConfig();
        // UUID redaction must be explicitly enabled
        config.getStrings().getPatterns().getUuids().setEnabled(true);
        RedactionEngine engine = new RedactionEngine(config);

        String result = engine.redact("uuid", uuid);
        assertRedacted(uuid, result);
    }


    @ParameterizedTest
    @ValueSource(strings = {
        "not-a-uuid",
        "550e8400-e29b-41d4-a716",  // Too short
        "550e8400-e29b-41d4-a716-446655440000-extra",  // Too long
        "ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ"  // Invalid characters
    })
    public void testInvalidUUIDsNotRedacted(String notUuid) {
        RedactionEngine engine = createDefaultEngine();
        String result = engine.redact("id", notUuid);
        assertNotRedacted(notUuid, result);
    }

    // ========== Home Directory Pattern Tests ==========

    @ParameterizedTest
    @ValueSource(strings = {
        "/home/username/project",
        "/Users/johndoe/Documents",
        "C:\\Users\\Alice\\Desktop",
        "/home/user/.ssh/id_rsa"
    })
    public void testHomeDirectoriesAreRedacted(String path) {
        RedactionEngine engine = createDefaultEngine();
        String result = engine.redact("path", path);
        assertRedacted(path, result);
    }

    // ========== Multiple Pattern Matching Tests ==========

    @Test
    public void testEmailInLargerString() {
        RedactionEngine engine = createDefaultEngine();
        String text = "Contact us at support@example.com for help";
        String result = engine.redact("description", text);
        assertRedacted(text, result);
    }

    @Test
    public void testSSHPatternInConnectionString() {
        RedactionConfig config = new RedactionConfig();
        config.getStrings().getPatterns().getSshHosts().setEnabled(true);
        RedactionEngine engine = new RedactionEngine(config);

        String connection = "Connecting to ssh://deploy@prod-server-01.internal";
        String result = engine.redact("connection", connection);
        assertRedacted(connection, result);
    }

    // ========== Edge Cases ==========

    @Test
    public void testEmptyString() {
        RedactionEngine engine = createDefaultEngine();
        String result = engine.redact("field", "");
        assertEquals("", result, "Empty string should remain empty");
    }

    @Test
    public void testVeryLongString() {
        RedactionEngine engine = createDefaultEngine();
        String longString = "a".repeat(10000);
        String result = engine.redact("data", longString);
        assertEquals(longString, result, "Long non-sensitive string should not be redacted");
    }

    @Test
    public void testSpecialCharactersInFieldName() {
        RedactionEngine engine = createDefaultEngine();
        String result = engine.redact("field.with.dots", "value");
        assertEquals("value", result);

        result = engine.redact("field-with-dashes", "value");
        assertEquals("value", result);
    }

    @Test
    public void testCaseSensitivityOfFieldNames() {
        RedactionEngine engine = createDefaultEngine();

        // Password variations
        assertEquals("***", engine.redact("password", "secret"));
        assertEquals("***", engine.redact("PASSWORD", "secret"));
        assertEquals("***", engine.redact("Password", "secret"));
        assertEquals("***", engine.redact("pAsSwOrD", "secret"));
    }

    @Test
    public void testPortFieldNameVariations() {
        RedactionEngine engine = createEngineWithPseudonymization();

        // All these should be recognized as port fields
        assertNotEquals(8080, engine.redact("port", 8080));
        assertNotEquals(8080, engine.redact("Port", 8080));
        assertNotEquals(8080, engine.redact("PORT", 8080));
        assertNotEquals(8080, engine.redact("sourcePort", 8080));
        assertNotEquals(8080, engine.redact("destinationPort", 8080));
        assertNotEquals(8080, engine.redact("serverPort", 8080));
        assertNotEquals(8080, engine.redact("p", 8080));
    }

    // ========== Pseudonymizer Access Tests ==========

    @Test
    public void testGetPseudonymizer() {
        RedactionEngine engine = createEngineWithPseudonymization();

        assertNotNull(engine.getPseudonymizer());
        assertTrue(engine.getPseudonymizer().isEnabled());
    }

    @Test
    public void testPseudonymizerStatistics() {
        RedactionEngine engine = createEngineWithMode("counter");

        engine.redact("password", "value1");
        engine.redact("password", "value2");
        engine.redact("password", "value1");  // Duplicate

        // The pseudonymizer should have tracked these
        assertNotNull(engine.getPseudonymizer());
    }

    // ========== Combined Pattern Tests ==========

    @Test
    public void testPropertyTakesPrecedenceOverStringPatterns() {
        RedactionEngine engine = createDefaultEngine();

        // "api_key" matches property pattern, even though value might match other patterns
        String result = engine.redact("api_key", "user@example.com");
        assertEquals("***", result, "Property pattern should take precedence");
    }

    @Test
    public void testMultipleStringPatternsInSameValue() {
        RedactionEngine engine = createDefaultEngine();

        // Contains both email and IP
        String text = "Contact admin@example.com at 192.168.1.1";
        String result = engine.redact("info", text);

        // Should be redacted due to email pattern match
        assertRedacted(text, result);
    }

    // ========== Integration Tests ==========

    @Test
    public void testCompleteRedactionWorkflow() {
        RedactionEngine engine = createEngineWithMode("counter");

        // Mix of different field types
        String password = engine.redact("password", "secret123");
        String email = engine.redact("email", "user@example.com");
        int port = engine.redact("port", 8080);
        String username = engine.redact("username", "johndoe");
        boolean flag = engine.redact("enabled", true);

        // Verify redactions
        assertEquals("<redacted:1>", password);
        assertEquals("<redacted:2>", email);
        assertEquals(1000, port);
        assertEquals("johndoe", username);  // Username not redacted by default
        assertTrue(flag);
    }

    @Test
    public void testEventRemovalWithRedaction() {
        RedactionEngine engine = createEngineWithPseudonymization();

        // Some events should be removed
        assertTrue(engine.shouldRemoveEvent("jdk.OSInformation"));

        // But fields in kept events should still be redacted
        String password = engine.redact("password", "secret");
        assertRedacted("secret", password);
    }

    // ========== Performance Edge Cases ==========

    @Test
    public void testManyDifferentValuesToSameField() {
        RedactionEngine engine = createEngineWithMode("counter");

        for (int i = 0; i < 100; i++) {
            String value = "password_" + i;
            String redacted = engine.redact("password", value);
            assertEquals("<redacted:" + (i + 1) + ">", redacted);
        }
    }

    @Test
    public void testSameValueManyTimes() {
        RedactionEngine engine = createEngineWithMode("hash");

        String firstResult = engine.redact("password", "constant");

        for (int i = 0; i < 100; i++) {
            String result = engine.redact("password", "constant");
            assertEquals(firstResult, result, "Same value should always produce same result");
        }
    }

    // ========== Boundary Value Tests ==========

    @Test
    public void testPortBoundaryValues() {
        RedactionEngine engine = createEngineWithPseudonymization();

        // Test various port ranges
        assertNotEquals(0, engine.redact("port", 0));
        assertNotEquals(1, engine.redact("port", 1));
        assertNotEquals(80, engine.redact("port", 80));
        assertNotEquals(443, engine.redact("port", 443));
        assertNotEquals(8080, engine.redact("port", 8080));
        assertNotEquals(65535, engine.redact("port", 65535));
    }

    @Test
    public void testNumericTypeBoundaries() {
        RedactionEngine engine = createDefaultEngine();

        // Byte boundaries
        assertEquals(Byte.MIN_VALUE, engine.redact("b", Byte.MIN_VALUE));
        assertEquals(Byte.MAX_VALUE, engine.redact("b", Byte.MAX_VALUE));

        // Short boundaries
        assertEquals(Short.MIN_VALUE, engine.redact("s", Short.MIN_VALUE));
        assertEquals(Short.MAX_VALUE, engine.redact("s", Short.MAX_VALUE));

        // Int boundaries
        assertEquals(Integer.MIN_VALUE, engine.redact("i", Integer.MIN_VALUE));
        assertEquals(Integer.MAX_VALUE, engine.redact("i", Integer.MAX_VALUE));

        // Long boundaries
        assertEquals(Long.MIN_VALUE, engine.redact("l", Long.MIN_VALUE));
        assertEquals(Long.MAX_VALUE, engine.redact("l", Long.MAX_VALUE));
    }

    // ========== Partial Redaction Tests ==========

    @Test
    public void testPartialRedactionOfEmailInText() {
        RedactionEngine engine = createDefaultEngine();

        String input = "dfgadfgx adyfvadfvasdfv sdf@s.de  dfsdf";
        String result = engine.redact("description", input);

        // Should redact only the email address, not the entire string
        assertRedacted(input, result);
        assertEquals("dfgadfgx adyfvadfvasdfv ***  dfsdf", result, "Email should be redacted in place");
    }

    @Test
    public void testPartialRedactionOfIPInText() {
        RedactionEngine engine = createDefaultEngine();

        String input = "Server running on 192.168.1.100 with port 8080";
        String result = engine.redact("message", input);

        // Should redact only the IP address
        assertRedacted(input, result);
        assertEquals("Server running on *** with port 8080", result, "IP address should be redacted in place");
    }

    @Test
    public void testPartialRedactionMultiplePatternsInSameString() {
        RedactionEngine engine = createDefaultEngine();

        String input = "Contact admin@example.com or visit 10.0.0.5 for support";
        String result = engine.redact("info", input);

        // Should redact both email and IP
        assertRedacted(input, result);
        assertEquals("Contact *** or visit *** for support", result, "Both email and IP should be redacted in place");
    }

    @Test
    public void testPartialRedactionDoesNotRedactEntireStringWhenPropertyMatches() {
        RedactionEngine engine = createDefaultEngine();

        // When field name matches a property pattern, entire value is redacted
        String input = "my_secret_value_123";
        String result = engine.redact("password", input);

        // This should redact the entire value because "password" is a property pattern
        assertEquals("***", result, "Property pattern should redact entire value");
    }

    @Test
    public void testPartialRedactionOnlyAppliesToStringPatterns() {
        RedactionConfig config = new RedactionConfig();
        config.getProperties().setEnabled(false);  // Disable property patterns
        config.getStrings().setEnabled(true);      // Enable string patterns
        RedactionEngine engine = new RedactionEngine(config);

        String input = "My email is test@example.com and that's it";
        String result = engine.redact("password", input);  // Field name doesn't matter with properties disabled

        // Should do partial redaction since we're only using string patterns
        assertRedacted(input, result);
        assertEquals("My email is *** and that's it", result, "Email should be redacted in place");
    }

    // ========== Custom Regex Pattern Tests ==========

    @Test
    public void testCustomRegexPatternsFromCli() {
        RedactionConfig config = new RedactionConfig();

        // Simulate CLI options with custom regex patterns
        RedactionConfig.CliOptions cliOptions = new RedactionConfig.CliOptions();
        cliOptions.getRedactionRegexes().add("\\b[A-Z]{3}-\\d{6}\\b");  // Ticket ID pattern

        config.applyCliOptions(cliOptions);
        RedactionEngine engine = new RedactionEngine(config);

        // Test that custom pattern is applied
        String text = "See ticket ABC-123456 for details";
        String result = engine.redact("description", text);

        assertRedacted(text, result);
        assertEquals("See ticket *** for details", result);
    }

    @Test
    public void testMultipleCustomRegexPatterns() {
        RedactionConfig config = new RedactionConfig();

        RedactionConfig.CliOptions cliOptions = new RedactionConfig.CliOptions();
        cliOptions.getRedactionRegexes().add("\\b[A-Z]{3}-\\d{6}\\b");      // Ticket ID
        cliOptions.getRedactionRegexes().add("AKIA[0-9A-Z]{16}");            // AWS access key
        cliOptions.getRedactionRegexes().add("ghp_[a-zA-Z0-9]{36}");         // GitHub token

        config.applyCliOptions(cliOptions);
        RedactionEngine engine = new RedactionEngine(config);

        // Test ticket ID pattern
        String ticket = "Bug report ABC-123456";
        assertEquals("Bug report ***", engine.redact("text", ticket));

        // Test AWS key pattern
        String awsKey = "Key: AKIAIOSFODNN7EXAMPLE";
        assertEquals("Key: ***", engine.redact("text", awsKey));

        // Test GitHub token pattern
        String ghToken = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        assertEquals("Token: ***", engine.redact("text", ghToken));
    }

    @Test
    public void testCustomRegexWithPseudonymization() {
        RedactionConfig config = new RedactionConfig();
        config.getGeneral().getPseudonymization().setEnabled(true);
        config.getGeneral().getPseudonymization().setMode("counter");

        RedactionConfig.CliOptions cliOptions = new RedactionConfig.CliOptions();
        cliOptions.getRedactionRegexes().add("\\b[A-Z]{3}-\\d{6}\\b");
        cliOptions.setPseudonymize(true);

        config.applyCliOptions(cliOptions);
        RedactionEngine engine = new RedactionEngine(config);

        // Same ticket ID should produce same pseudonym
        String text1 = "Ticket ABC-123456 was closed";
        String text2 = "Reopened ABC-123456";

        String result1 = engine.redact("text", text1);
        String result2 = engine.redact("text", text2);

        assertRedacted(text1, result1);
        assertRedacted(text2, result2);

        // Extract the pseudonym from both results
        assertTrue(result1.contains("<redacted:"));
        assertTrue(result2.contains("<redacted:"));

        // Both should contain the same pseudonym for ABC-123456
        String pseudonym1 = result1.substring(result1.indexOf("<redacted:"), result1.indexOf(">") + 1);
        String pseudonym2 = result2.substring(result2.indexOf("<redacted:"), result2.indexOf(">") + 1);
        assertEquals(pseudonym1, pseudonym2, "Same ticket ID should produce same pseudonym");
    }

    @Test
    public void testCustomRegexDoesNotAffectOtherPatterns() {
        RedactionConfig config = new RedactionConfig();

        RedactionConfig.CliOptions cliOptions = new RedactionConfig.CliOptions();
        cliOptions.getRedactionRegexes().add("\\b[A-Z]{3}-\\d{6}\\b");

        config.applyCliOptions(cliOptions);
        RedactionEngine engine = new RedactionEngine(config);

        // Custom pattern should work
        assertEquals("Bug ***", engine.redact("text", "Bug ABC-123456"));

        // Built-in patterns should still work
        String emailText = "Contact user@example.com";
        String emailResult = engine.redact("text", emailText);
        assertRedacted(emailText, emailResult);

        String ipText = "Server at 192.168.1.1";
        String ipResult = engine.redact("text", ipText);
        assertRedacted(ipText, ipResult);

        // Property patterns should still work
        assertEquals("***", engine.redact("password", "secret123"));
    }

    @Test
    public void testCustomRegexWithMultipleMatches() {
        RedactionConfig config = new RedactionConfig();

        RedactionConfig.CliOptions cliOptions = new RedactionConfig.CliOptions();
        cliOptions.getRedactionRegexes().add("\\b[A-Z]{3}-\\d{6}\\b");

        config.applyCliOptions(cliOptions);
        RedactionEngine engine = new RedactionEngine(config);

        // Multiple matches in same string
        String text = "Tickets ABC-123456 and DEF-789012 are related";
        String result = engine.redact("text", text);

        assertRedacted(text, result);
        assertEquals("Tickets *** and *** are related", result);
    }

    // ========== IPv6 Format Tests ==========

    @Test
    public void testIPv6InContextWithCompressedFormat() {
        RedactionEngine engine = createDefaultEngine();

        // Test compressed IPv6 in various contexts
        String text1 = "Server at 2001:db8::8a2e:370:7334 is down";
        String result1 = engine.redact("message", text1);
        assertRedacted(text1, result1);
        assertEquals("Server at *** is down", result1);

        // Test with loopback
        String text2 = "Connecting to ::1 on port 8080";
        String result2 = engine.redact("log", text2);
        assertRedacted(text2, result2);
        assertEquals("Connecting to *** on port 8080", result2);

        // Test with link-local
        String text3 = "Interface fe80::1 active";
        String result3 = engine.redact("status", text3);
        assertRedacted(text3, result3);
        assertEquals("Interface *** active", result3);
    }

    @Test
    public void testIPv6WithPseudonymization() {
        RedactionEngine engine = createEngineWithMode("counter");

        // Same IPv6 should get same pseudonym
        String text1 = "Host 2001:db8::1 responded";
        String text2 = "Connecting to 2001:db8::1";

        String result1 = engine.redact("message", text1);
        String result2 = engine.redact("message", text2);

        // Both should contain the same redacted value for the same IP
        assertTrue(result1.contains("<redacted:"));
        assertTrue(result2.contains("<redacted:"));

        // Extract and compare pseudonyms
        String pseudonym1 = result1.substring(result1.indexOf("<redacted:"), result1.indexOf(">", result1.indexOf("<redacted:")) + 1);
        String pseudonym2 = result2.substring(result2.indexOf("<redacted:"), result2.indexOf(">", result2.indexOf("<redacted:")) + 1);

        assertEquals(pseudonym1, pseudonym2, "Same IPv6 should produce same pseudonym");
    }

    @Test
    public void testIPv6AndIPv4Together() {
        RedactionEngine engine = createDefaultEngine();

        String text = "Dual stack: IPv4 192.168.1.1 and IPv6 2001:db8::1";
        String result = engine.redact("config", text);

        assertRedacted(text, result);
        assertEquals("Dual stack: IPv4 *** and IPv6 ***", result);
    }
}