package me.bechberger.jfrredact.config;

import me.bechberger.jfrredact.ConfigLoader;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for StringConfig pattern parsing including SSH hosts.
 */
public class StringConfigTest {

    @Test
    public void testDefaultStringConfig() {
        StringConfig config = new StringConfig();

        assertTrue(config.isEnabled());
        assertFalse(config.isRedactInMethodNames());
        assertFalse(config.isRedactInClassNames());
        assertFalse(config.isRedactInThreadNames());

        // Verify default patterns
        assertNotNull(config.getPatterns());
        assertTrue(config.getPatterns().getHomeDirectories().isEnabled());
        assertTrue(config.getPatterns().getEmails().isEnabled());
        assertTrue(config.getPatterns().getIpAddresses().isEnabled());
        assertFalse(config.getPatterns().getUuids().isEnabled());  // Disabled by default
        assertFalse(config.getPatterns().getSshHosts().isEnabled());  // Disabled by default
    }

    @Test
    public void testSshHostPatternsDefault() {
        StringConfig config = new StringConfig();
        var sshConfig = config.getPatterns().getSshHosts();

        assertFalse(sshConfig.isEnabled());  // Disabled by default
        assertEquals(4, sshConfig.getPatterns().size());

        // Verify default patterns are present
        assertTrue(sshConfig.getPatterns().contains("ssh://[a-zA-Z0-9.-]+"));
        assertTrue(sshConfig.getPatterns().contains("(?:ssh|sftp)://(?:[^@]+@)?[a-zA-Z0-9.-]+"));
    }

    @Test
    public void testHomeDirectoryPatternsDefault() {
        StringConfig config = new StringConfig();
        var homeConfig = config.getPatterns().getHomeDirectories();

        assertTrue(homeConfig.isEnabled());
        assertEquals(3, homeConfig.getRegexes().size());

        // Verify macOS, Windows, and Linux patterns
        assertTrue(homeConfig.getRegexes().stream().anyMatch(r -> r.contains("/Users/")));
        assertTrue(homeConfig.getRegexes().stream().anyMatch(r -> r.contains("C:")));
        assertTrue(homeConfig.getRegexes().stream().anyMatch(r -> r.contains("/home/")));
    }

    @Test
    public void testEmailPattern() {
        StringConfig config = new StringConfig();
        var emailConfig = config.getPatterns().getEmails();

        assertTrue(emailConfig.isEnabled());
        assertNotNull(emailConfig.getRegex());
        assertTrue(emailConfig.getRegex().contains("@"));
    }

    @Test
    public void testIpAddressPatterns() {
        StringConfig config = new StringConfig();
        var ipConfig = config.getPatterns().getIpAddresses();

        assertTrue(ipConfig.isEnabled());
        assertNotNull(ipConfig.getIpv4());
        assertNotNull(ipConfig.getIpv6());
    }

    @Test
    public void testUuidPattern() {
        StringConfig config = new StringConfig();
        var uuidConfig = config.getPatterns().getUuids();

        assertFalse(uuidConfig.isEnabled());  // Disabled by default
        assertNotNull(uuidConfig.getRegex());
        assertTrue(uuidConfig.getRegex().contains("-"));
    }

    @Test
    public void testCustomPatterns() {
        StringConfig config = new StringConfig();
        var customPatterns = config.getPatterns().getCustom();

        assertNotNull(customPatterns);
        assertTrue(customPatterns.isEmpty());  // Empty by default
    }

    @Test
    public void testAddCustomPattern() {
        StringConfig config = new StringConfig();

        StringConfig.CustomPatternConfig customPattern = new StringConfig.CustomPatternConfig();
        customPattern.setName("aws_keys");
        customPattern.setRegex("AKIA[0-9A-Z]{16}");

        config.getPatterns().getCustom().add(customPattern);

        assertEquals(1, config.getPatterns().getCustom().size());
        assertEquals("aws_keys", config.getPatterns().getCustom().getFirst().getName());
    }

    @Test
    public void testMergeWithParent() {
        StringConfig parent = new StringConfig();
        parent.getPatterns().getSshHosts().getPatterns().add("custom_ssh_pattern");

        StringConfig child = new StringConfig();
        child.getPatterns().getSshHosts().getPatterns().clear();
        child.getPatterns().getSshHosts().getPatterns().add("child_ssh_pattern");

        child.mergeWith(parent);

        // Should have both parent and child patterns
        assertTrue(child.getPatterns().getSshHosts().getPatterns().contains("custom_ssh_pattern"));
        assertTrue(child.getPatterns().getSshHosts().getPatterns().contains("child_ssh_pattern"));
    }

    @Test
    public void testLoadDefaultPresetWithStringPatterns() throws IOException {
        ConfigLoader loader = new ConfigLoader();
        RedactionConfig config = loader.load("default");

        assertNotNull(config.getStrings());
        assertTrue(config.getStrings().isEnabled());

        // Verify string patterns are loaded
        assertNotNull(config.getStrings().getPatterns());
        assertNotNull(config.getStrings().getPatterns().getSshHosts());
    }

    @Test
    public void testCliCustomRegexPatterns() throws IOException {
        ConfigLoader loader = new ConfigLoader();
        RedactionConfig config = loader.load("default");

        // Simulate CLI options with custom regex patterns
        RedactionConfig.CliOptions cliOptions = new RedactionConfig.CliOptions();
        cliOptions.getRedactionRegexes().add("\\b[A-Z]{3}-\\d{6}\\b");  // Ticket ID pattern
        cliOptions.getRedactionRegexes().add("AKIA[0-9A-Z]{16}");       // AWS access key pattern

        // Apply CLI options
        config.applyCliOptions(cliOptions);

        // Verify custom patterns were added
        var customPatterns = config.getStrings().getPatterns().getCustom();
        assertEquals(2, customPatterns.size());

        assertEquals("cli_pattern_0", customPatterns.get(0).getName());
        assertEquals("\\b[A-Z]{3}-\\d{6}\\b", customPatterns.get(0).getRegex());

        assertEquals("cli_pattern_1", customPatterns.get(1).getName());
        assertEquals("AKIA[0-9A-Z]{16}", customPatterns.get(1).getRegex());
    }

    @Test
    public void testCliCustomRegexPatternsWithExistingCustomPatterns() throws IOException {
        ConfigLoader loader = new ConfigLoader();
        RedactionConfig config = loader.load("default");

        // Add a custom pattern via config
        StringConfig.CustomPatternConfig existingPattern = new StringConfig.CustomPatternConfig();
        existingPattern.setName("jwt_tokens");
        existingPattern.setRegex("eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+");
        config.getStrings().getPatterns().getCustom().add(existingPattern);

        // Now add CLI patterns
        RedactionConfig.CliOptions cliOptions = new RedactionConfig.CliOptions();
        cliOptions.getRedactionRegexes().add("\\b[A-Z]{3}-\\d{6}\\b");

        config.applyCliOptions(cliOptions);

        // Verify both existing and CLI patterns are present
        var customPatterns = config.getStrings().getPatterns().getCustom();
        assertEquals(2, customPatterns.size());

        // Existing pattern still there
        assertEquals("jwt_tokens", customPatterns.get(0).getName());
        assertEquals("eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+", customPatterns.get(0).getRegex());

        // CLI pattern added with correct name (size was 1 when added)
        assertEquals("cli_pattern_1", customPatterns.get(1).getName());
        assertEquals("\\b[A-Z]{3}-\\d{6}\\b", customPatterns.get(1).getRegex());
    }
}