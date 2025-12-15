jfr-redact
==========

[![CI](https://github.com/parttimenerd/jfr-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/parttimenerd/jfr-redact/actions/workflows/ci.yml)

__This is an early prototype of the SapMachine team, use at your own risk.__
__We don't provide any guarantees regarding functionality.__

A tool to redact sensitive information from Java Flight Recorder (JFR) recordings and text files,
replacing it with `***`.

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Development](#development)
- [Support & Contributing](#support-feedback-contributing)
- [License](#license)

## Quick Start

**Redact a JFR file with default settings:**
```bash
# Download the JAR from releases
java -jar jfr-redact.jar redact recording.jfr redacted.jfr
```

**Redact a Java error log (hs_err_pid*.log):**
```bash
java -jar jfr-redact.jar redact-text hs_err_pid12345.log hs_err_redacted.log

# Use the hserr preset optimized for crash reports:
java -jar jfr-redact.jar redact-text hs_err_pid12345.log --preset hserr
```

That's it! The tool will automatically redact:
- Passwords, tokens, API keys, and other sensitive properties
- User home directories and file paths
- Email addresses and IP addresses
- System environment variables and process information

## Features

- **Property Redaction**: Redact sensitive properties in events with `key` and `value` fields
  - Patterns: password, passwort, pwd, secret, token, key, ... (case-insensitive)
- **Event Removal**: Remove entire event types that could leak information
  - Examples: jdk.OSInformation, SystemProcess, InitialEnvironmentVariable, ProcessStart
- **Event Filtering**: Advanced filtering similar to `jfr scrub` command ([docs](https://docs.oracle.com/en/java/javase/21/docs/specs/man/jfr.html))
  - Filter by event name, category, or thread name
  - Supports glob patterns (*, ?) and comma-separated lists
  - Include/exclude filters with flexible combinations
- **String Pattern Redaction**: Redact sensitive patterns in string fields
  - Home folders: `/Users/[^/]+`, `C:\Users\[a-zA-Z0-9_\-]+`, `/home/[^/]+`
  - Email addresses, UUIDs, IP addresses
  - Configurable to exclude method names, class names, or thread names
- **Network Redaction**: Redact ports and addresses from SocketRead/SocketWrite events
- **Path Redaction**: Redact directory paths while keeping filenames (configurable)
- **Pseudonymization**: Preserve relationships between values while protecting data
  - Hash mode: Consistent mapping to pseudonyms (e.g., `<redacted:a1b2c3>`)
  - Counter mode: Sequential numbering (value1→1, value2→2)
  - Realistic mode: Generate plausible alternatives (e.g., `john.doe@company.com` → `alice.smith@test.com`)
  - **Custom replacements**: Define specific mappings in config (e.g., `johndoe` → `alice`, `/home/johndoe` → `/home/testuser`)
  - Optional, enabled via `--pseudonymize` flag
- **Text File Redaction**: Apply the same redaction patterns to arbitrary text files
  - Perfect for redacting Java error logs (hs_err_pid*.log) which contain system properties, environment variables, and file paths

## Installation

This tool requires Java 21 or higher.

### As a Command-Line Tool

Download the standalone JAR from the [releases page](https://github.com/parttimenerd/jfr-redact/releases).

### Using JBang

```bash
jbang jfr-redact@parttimenerd/jfr-redact
```

### As a Library (Maven/Gradle)

Use jfr-redact as a library to programmatically redact JFR files in your own applications:

**Maven:**
```xml
<dependency>
  <groupId>me.bechberger</groupId>
  <artifactId>jfr-redact</artifactId>
  <version>0.1.0</version>
</dependency>
```

**Gradle:**
```gradle
implementation 'me.bechberger:jfr-redact:0.1.0'
```

## Usage

### JFR File Redaction

```bash
# Use default preset (recommended for most cases)
java -jar jfr-redact.jar redact recording.jfr redacted.jfr

# Use strict preset (maximum redaction)
java -jar jfr-redact.jar redact recording.jfr redacted.jfr --preset strict

# Use custom configuration file
java -jar jfr-redact.jar recording.jfr redacted.jfr --config my-config.yaml

# Enable pseudonymization to preserve relationships between values
java -jar jfr-redact.jar recording.jfr redacted.jfr --pseudonymize

# Use pseudonymization with a specific preset
java -jar jfr-redact.jar recording.jfr redacted.jfr --preset strict --pseudonymize

# Filter events (similar to jfr scrub command)
# Keep only specific events
java -jar jfr-redact.jar recording.jfr redacted.jfr --include-events "jdk.ThreadSleep,jdk.JavaMonitorWait"

# Exclude specific event patterns
java -jar jfr-redact.jar recording.jfr redacted.jfr --exclude-events "jdk.GC*"

# Filter by category
java -jar jfr-redact.jar recording.jfr redacted.jfr --include-categories "Java Application"

# Filter by thread name
java -jar jfr-redact.jar recording.jfr redacted.jfr --exclude-threads "GC Thread*"

# Combine multiple filters
java -jar jfr-redact.jar recording.jfr redacted.jfr \
  --include-events "jdk.*" \
  --exclude-categories "Flight Recorder" \
  --exclude-threads "Service Thread"
```

### Text File Redaction

The tool also works with any text file (not just JFR), applying the same redaction patterns:

```bash
# Redact a Java error log file (hs_err_pid*.log)
java -jar jfr-redact.jar redact-text hs_err_pid12345.log hs_err_pid12345.redacted.log

# Use the hserr preset optimized for crash reports
java -jar jfr-redact.jar redact-text hs_err_pid12345.log --preset hserr

# Redact an application log file
java -jar jfr-redact.jar redact-text app.log app.redacted.log --preset strict

# Redact any text file with pseudonymization
java -jar jfr-redact.jar redact-text debug-output.txt debug-output.redacted.txt --pseudonymize
```
Supports piping from stdin and writing to stdout:

```bash
cat hs_err_pid12345.log | java -jar jfr-redact.jar redact-text - -
```

### Command-Line Options

<details>
<summary><strong>Redact Command</strong> (default) - Redact JFR recordings</summary>

<!-- BEGIN help_redact -->
```
Usage: jfr-redact redact [-hqvV] [--debug] [--dry-run] [--pseudonymize]
                         [--stats] [--config=<file|url>] [--preset=<preset>]
                         [--pseudonymize-mode=<mode>] [--seed=<seed>]
                         [--add-redaction-regex=<pattern>]...
                         [--exclude-categories=<filter>]...
                         [--exclude-events=<filter>]...
                         [--exclude-threads=<filter>]...
                         [--include-categories=<filter>]...
                         [--include-events=<filter>]...
                         [--include-threads=<filter>]...
                         [--remove-event=<type>]... <input.jfr> [<output.jfr>]
Redact sensitive information from Java Flight Recorder (JFR) recordings
      <input.jfr>           Input JFR file to redact
      [<output.jfr>]        Output JFR file with redacted data (default:
                              <input>.redacted.jfr)
      --add-redaction-regex=<pattern>
                            Add a custom regular expression pattern for string
                              redaction. This option can be specified multiple
                              times to add multiple patterns. Patterns are
                              applied to string fields in events.
      --config=<file|url>   Load configuration from a YAML file or URL
      --debug               Enable debug output (DEBUG level logging)
      --dry-run             Process the file without writing output, useful for
                              testing configuration with --stats
      --exclude-categories=<filter>
                            Exclude events matching a category name
                              (comma-separated list, supports glob patterns).
                              Similar to jfr scrub --exclude-categories.
      --exclude-events=<filter>
                            Exclude events matching an event name
                              (comma-separated list, supports glob patterns).
                              Similar to jfr scrub --exclude-events.
      --exclude-threads=<filter>
                            Exclude events matching a thread name
                              (comma-separated list, supports glob patterns).
                              Similar to jfr scrub --exclude-threads.
  -h, --help                Show this help message and exit.
      --include-categories=<filter>
                            Select events matching a category name
                              (comma-separated list, supports glob patterns).
                              Similar to jfr scrub --include-categories.
      --include-events=<filter>
                            Select events matching an event name
                              (comma-separated list, supports glob patterns).
                              Similar to jfr scrub --include-events.
      --include-threads=<filter>
                            Select events matching a thread name
                              (comma-separated list, supports glob patterns).
                              Similar to jfr scrub --include-threads.
      --preset=<preset>     Use a predefined configuration preset. Valid
                              values: default, strict, hserr (default: default)
      --pseudonymize        Enable pseudonymization mode. When enabled, the
                              same sensitive value always maps to the same
                              pseudonym (e.g., &lt;redacted:a1b2c3&gt;),
                              preserving relationships across events. Without
                              this flag, all values are redacted to ***.
      --pseudonymize-mode=<mode>
                            Pseudonymization mode (requires --pseudonymize).
                              Valid values: hash (default, stateless
                              deterministic), counter (sequential numbers),
                              realistic (plausible alternatives like
                              alice@example.com)
  -q, --quiet               Minimize output (only show errors and completion
                              message)
      --remove-event=<type> Remove an additional event type from the output.
                              This option can be specified multiple times to
                              remove multiple event types.
      --seed=<seed>         Seed for reproducible pseudonymization (only with
                              --pseudonymize)
      --stats               Show statistics after redaction (events processed,
                              removed, redactions applied)
  -v, --verbose             Enable verbose output (INFO level logging)
  -V, --version             Print version information and exit.

Examples:

  Simple redaction with default preset:
    jfr-redact redact recording.jfr
    (creates recording.redacted.jfr)

  Specify output file:
    jfr-redact redact recording.jfr output.jfr

  Strict preset with pseudonymization:
    jfr-redact redact recording.jfr --preset strict --pseudonymize

  Custom config with additional event removal:
    jfr-redact redact recording.jfr --config my-config.yaml --remove-event jdk.
CustomEvent

  Add custom redaction pattern:
    jfr-redact redact recording.jfr --add-redaction-regex '\b[A-Z]{3}-\d{6}\b'
```
<!-- END help_redact -->

</details>

<details>
<summary><strong>Redact-Text Command</strong> - Redact text files (logs, hs_err, etc.)</summary>

<!-- BEGIN help_redact_text -->
```
Usage: jfr-redact redact-text [-hqvV] [--debug] [--pseudonymize] [--stats]
                              [--config=<file|url>] [--preset=<preset>]
                              [--pseudonymize-mode=<mode>] [--seed=<seed>]
                              [--add-redaction-regex=<pattern>]... <input-file>
                              [<output-file>]
Redact sensitive information from text files (logs, configuration files, etc.)
      <input-file>          Input text file to redact
      [<output-file>]       Output file with redacted data (default: <input>.
                              redacted.<ext>)
      --add-redaction-regex=<pattern>
                            Add a custom regular expression pattern for string
                              redaction. This option can be specified multiple
                              times to add multiple patterns.
      --config=<file|url>   Load configuration from a YAML file or URL
      --debug               Enable debug output (DEBUG level logging)
  -h, --help                Show this help message and exit.
      --preset=<preset>     Use a predefined configuration preset. Valid
                              values: default, strict, hserr (default: default)
      --pseudonymize        Enable pseudonymization mode. When enabled, the
                              same sensitive value always maps to the same
                              pseudonym (e.g., &lt;redacted:a1b2c3&gt;),
                              preserving relationships across lines. Without
                              this flag, all values are redacted to ***.
      --pseudonymize-mode=<mode>
                            Pseudonymization mode (requires --pseudonymize).
                              Valid values: hash (default, stateless
                              deterministic), counter (sequential numbers),
                              realistic (plausible alternatives like
                              alice@example.com)
  -q, --quiet               Minimize output (only show errors and completion
                              message)
      --seed=<seed>         Seed for reproducible pseudonymization (only with
                              --pseudonymize)
      --stats               Show statistics after redaction
  -v, --verbose             Enable verbose output (INFO level logging)
  -V, --version             Print version information and exit.

Examples:

  Redact a log file with default preset:
    jfr-redact redact-text application.log
    (creates application.redacted.log)

  Use hserr preset for Java crash reports:
    jfr-redact redact-text hs_err_pid12345.log --preset hserr

  Read from stdin, write to stdout:
    cat hs_err_pid12345.log | jfr-redact redact-text - -

  Use strict preset:
    jfr-redact redact-text application.log --preset strict

  Custom config with pseudonymization:
    jfr-redact redact-text app.log --config my-config.yaml --pseudonymize

  Add custom redaction pattern:
    jfr-redact redact-text app.log --add-redaction-regex '\b[A-Z]{3}-\d{6}\b'
```
<!-- END help_redact_text -->

</details>

<details>
<summary><strong>Generate-Config Command</strong> - Generate configuration templates</summary>

<!-- BEGIN help_generate_config -->
```
Usage: jfr-redact generate-config [-hqvV] [--debug] [--minimal] [-o=<file>]
                                  [--preset=<preset>] [<output.yaml>]
Generate a configuration template for JFR redaction
      [<output.yaml>]     Output file for the configuration (default: stdout)
      --debug             Enable debug output (DEBUG level logging)
  -h, --help              Show this help message and exit.
      --minimal           Generate minimal configuration template
  -o, --output=<file>     Output file for the configuration
      --preset=<preset>   Base the configuration on a preset. Valid values:
                            default, strict, hserr
  -q, --quiet             Minimize output (only show errors and completion
                            message)
  -v, --verbose           Enable verbose output (INFO level logging)
  -V, --version           Print version information and exit.

Examples:

  Generate default template to stdout:
    jfr-redact generate-config

  Generate template to file:
    jfr-redact generate-config -o my-config.yaml

  Generate from preset:
    jfr-redact generate-config --preset strict -o my-config.yaml

  Generate minimal config:
    jfr-redact generate-config --minimal -o minimal-config.yaml
```
<!-- END help_generate_config -->

</details>

<details>
<summary><strong>Test/Validate Command</strong> - Test or validate configuration</summary>

<!-- BEGIN help_test -->
```
Usage: jfr-redact test [-hqvV] [--debug] [--pseudonymize] [--config=<file|url>]
                       [--event=<type>] [--preset=<preset>] [--property=<name>]
                       [--pseudonymize-mode=<mode>] [--seed=<seed>]
                       [--thread=<name>] [--value=<value>]
Test configuration by showing how specific values would be redacted
Also validates configuration when run without test values
      --config=<file|url>   Load configuration from a YAML file or URL
      --debug               Enable debug output (DEBUG level logging)
      --event=<type>        Event type to test (e.g., jdk.JavaMonitorEnter)
  -h, --help                Show this help message and exit.
      --preset=<preset>     Use a predefined configuration preset. Valid
                              values: default, strict, hserr (default: default)
      --property=<name>     Property/field name to test (e.g., address, message)
      --pseudonymize        Enable pseudonymization mode
      --pseudonymize-mode=<mode>
                            Pseudonymization mode (requires --pseudonymize).
                              Valid values: hash (default, stateless
                              deterministic), counter (sequential numbers),
                              realistic (plausible alternatives like
                              alice@example.com)
  -q, --quiet               Minimize output (only show errors and completion
                              message)
      --seed=<seed>         Seed for reproducible pseudonymization (only with
                              --pseudonymize)
      --thread=<name>       Thread name to test filtering
  -v, --verbose             Enable verbose output (INFO level logging)
  -V, --version             Print version information and exit.
      --value=<value>       Value to test redaction on

Examples:

  Validate a configuration:
    jfr-redact test --config my-config.yaml
    jfr-redact validate --config my-config.yaml

  Test a property redaction:
    jfr-redact test --config my-config.yaml --event jdk.JavaMonitorEnter
--property address --value '0x7f8a4c001000'

  Test thread name filtering:
    jfr-redact test --config my-config.yaml --thread 'MyThread-1'

  Test string redaction:
    jfr-redact test --preset strict --value 'user@example.com'
```
<!-- END help_test -->

</details>

<details>
<summary><strong>Generate-Schema Command</strong> - Generate JSON Schema for IDE support</summary>

<!-- BEGIN help_generate_schema -->
```
Usage: jfr-redact generate-schema [-hqvV] [--debug] [<output.json>]
Generate JSON Schema for the YAML configuration files
      [<output.json>]   Output file for the JSON schema (default: stdout)
      --debug           Enable debug output (DEBUG level logging)
  -h, --help            Show this help message and exit.
  -q, --quiet           Minimize output (only show errors and completion
                          message)
  -v, --verbose         Enable verbose output (INFO level logging)
  -V, --version         Print version information and exit.

Examples:

  Generate schema to stdout:
    jfr-redact generate-schema

  Generate schema to a file:
    jfr-redact generate-schema config-schema.json
```
<!-- END help_generate_schema -->

</details>

## Configuration

A customizable template is available at [config-template.yaml](config-template.yaml).

**Configuration Inheritance:**

Configuration File Format
-------------------------
- Preset names: `default`, `strict`
- File paths: `./my-parent-config.yaml`, `/absolute/path/to/config.yaml`
- URLs: `https://example.com/configs/base.yaml`, `file:///path/to/config.yaml`

<details><summary>Example with URL parent</summary>

```yaml
# Save as: my-config.yaml

# You can base your configuration on a preset and override specific options
# Or build from scratch by commenting out the parent line
#   parent: default

# Property redaction - matches patterns in field names
properties:
  enabled: true
  case_sensitive: false  # If true, patterns are case-sensitive

  # Full match mode: if true, pattern must match entire field name
  # If false (default), pattern can match anywhere in field name
  # Example with pattern "password":
  #   full_match=false: matches "password", "user_password", "myPasswordField"
  #   full_match=true:  matches only "password" (exact match)
  full_match: false

  patterns:  # Regex patterns to match in field names
    - (pass(word|wort|wd)?|pwd)  # Matches: password, passwort, passwd, pwd
    - secret
    - token
    - (api[_-]?)?key       # Matches: key, api_key, api-key, apikey
    - auth
    - credential

    # - myapp_secret
    # - custom_token

# Event removal - completely remove these event types from the recording
events:
  remove_enabled: true
  removed_types:
    - jdk.OSInformation
    - jdk.SystemProcess
    - jdk.InitialEnvironmentVariable
    - jdk.ProcessStart
    # Add additional event types to remove:
    # - jdk.SystemProperty
    # - jdk.NativeLibrary

  # Advanced filtering (similar to jfr scrub command)
  # See: https://docs.oracle.com/en/java/javase/21/docs/specs/man/jfr.html
  # Filters are comma-separated lists and support glob patterns (* and ?)
  filtering:
    # Include only events matching these patterns (if specified, only matching events are kept)
    include_events: []
    # Examples:
    # - jdk.ThreadSleep,jdk.JavaMonitorWait  # Only these specific events
    # - jdk.*                                 # All JDK events
    # - my.app.*                              # All events from my.app package

    # Exclude events matching these patterns
    exclude_events: []
    # Examples:
    # - jdk.GCPhasePause*                    # Exclude all GC phase pause events
    # - jdk.ThreadSleep                      # Exclude thread sleep events

    # Include only events from these categories
    include_categories: []
    # Examples:
    # - Java Application                     # Only application events
    # - Java Virtual Machine                 # Only JVM events

    # Exclude events from these categories
    exclude_categories: []
    # Examples:
    # - Flight Recorder                      # Exclude JFR internal events

    # Include only events from these threads
    include_threads: []
    # Examples:
    # - main                                 # Only main thread
    # - worker-*                             # All worker threads

    # Exclude events from these threads
    exclude_threads: []
    # Examples:
    # - GC Thread*                           # Exclude all GC threads
    # - Service Thread                       # Exclude service thread

# String pattern redaction - redact matching patterns in string fields
strings:
  enabled: true

  # Normally you don't want to redact code artifacts
  redact_in_method_names: false
  redact_in_class_names: false
  redact_in_thread_names: false

  patterns:
    # Home directory paths
    home_directories:
      enabled: true
      regexes:
        - '/Users/[^/]+'                    # macOS: /Users/username
        - 'C:\\Users\\[a-zA-Z0-9_\-]+'     # Windows: C:\Users\username
        - '/home/[^/]+'                     # Linux: /home/username

    # Email addresses
    emails:
      enabled: true
      regex: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

    # UUIDs (often used as identifiers)
    uuids:
      enabled: false  # Set to true if UUIDs are sensitive in your context
      regex: '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

    # IP addresses
    ip_addresses:
      enabled: true
      ipv4: '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
      ipv6: '\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'

    # SSH host patterns - redact hostnames in SSH connection strings
    # Matches: user@hostname, ssh://hostname, hostname:port
    ssh_hosts:
      enabled: false  # Set to true if SSH hosts are sensitive
      patterns:
        - 'ssh://[a-zA-Z0-9.-]+'                           # ssh://hostname
        - '(?:ssh|sftp)://(?:[^@]+@)?[a-zA-Z0-9.-]+'      # ssh://user@hostname
        - '[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+(?::[0-9]+)?'     # user@host or user@host:port
        - '(?<=ssh\s)[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+'       # after "ssh " command

    # Custom patterns - add your own regex patterns here
    custom:
    # Example: AWS access keys
    # - name: aws_access_keys
    #   regex: 'AKIA[0-9A-Z]{16}'

    # Example: JWT tokens
    # - name: jwt_tokens
    #   regex: 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'

# Network event redaction - redact addresses/ports in socket events
network:
  enabled: true
  redact_ports: true
  redact_addresses: true
  keep_local_addresses: false  # Set to true to preserve localhost/127.0.0.1
  event_types:
    - jdk.SocketRead
    - jdk.SocketWrite

# Path redaction - control how file paths are redacted
paths:
  enabled: true
  mode: keep_filename  # Options: keep_filename, redact_all, keep_all
  # keep_filename: /path/to/***/ and filename
  # redact_all: complete path becomes ***
  # keep_all: path unchanged
  fields:
    - path
    - directory
    - file
    - destination

# General settings
general:
  redaction_text: "***"  # Text to replace redacted values with

  # Partial redaction - show some info while hiding sensitive parts
  # When false: "my_secret_password" -> "***"
  # When true:  "my_secret_password" -> "my***" (shows prefix/suffix)
  # Useful for: debugging (identify which value without exposing it),
  #             compliance (show value format without actual data),
  #             log analysis (distinguish between different redacted values)
  partial_redaction: false

  # Pseudonymization - preserves relationships between values
  # When enabled, the same input value always maps to the same redacted output
  # e.g., "user@example.com" -> "<redacted:a1b2c3>" (consistent across the recording)
  pseudonymization:
    enabled: false  # Set to true to enable pseudonymization

    # Pseudonymization mode:
    # - "hash": Hash-based (stateless, deterministic, default)
    #           No state required, same value always produces same hash
    #           Best for: Most use cases, low memory, deterministic
    # - "counter": Simple counter (stateful, requires hash map)
    #              Maps values to sequential numbers: value1->1, value2->2
    #              Best for: Debugging, smaller output, when you want readable IDs
    # - "realistic": Generates plausible-looking alternatives (stateful)
    #                Replaces sensitive data with realistic alternatives
    #                Examples: "john.doe@company.com" -> "alice.smith@test.com"
    #                          "/home/johndoe" -> "/home/user01"
    #                          "johndoe" -> "user01"
    #                Best for: Creating shareable test data, demos, public bug reports
    mode: "hash"

    format: "redacted"  # Options: "redacted", "hash", "custom"
    # - redacted: <redacted:abc123>
    # - hash: <hash:abc123>
    # - custom: use custom_prefix and custom_suffix
    custom_prefix: "<redacted:"  # Used when format is "custom"
    custom_suffix: ">"
    hash_length: 8  # Length of hash suffix (6-32), only for mode="hash"
    hash_algorithm: "SHA-256"  # Options: SHA-256, SHA-1, MD5, only for mode="hash"

    # Scope of pseudonymization - what types of redacted values to pseudonymize
    scope:
      properties: true      # Property values (passwords, tokens, etc.)
      strings: true         # String pattern matches (emails, IPs, etc.)
      network: true         # Network addresses
      paths: true           # File paths
      ports: true           # Port numbers (always uses counter, mapped to 1000+ range)
      # Example: port 8080 -> 1001, port 443 -> 1002

    # Custom replacements for specific values (highest priority, overrides all modes)
    # Map exact values to specific replacements
    # Useful for replacing known usernames, email addresses, or paths
    replacements:
    # Example username replacements:
    # "johndoe": "alice"
    # "admin": "user01"

    # Example email replacements:
    # "john.doe@company.com": "user@example.com"
    # "admin@internal.net": "contact@test.org"

    # Example path replacements:
    # "/home/johndoe": "/home/testuser"
    # "C:\\Users\\JohnDoe": "C:\\Users\\TestUser"
    # "/Users/johndoe": "/Users/testuser"

    # Pattern-based replacement generators (using RgxGen)
    # Define regex patterns for generating realistic replacements by pattern type
    #
    # Two modes of operation:
    # 1. Redaction mode (pseudonymization disabled):
    #    - Generates a random value from the pattern each time
    #    - Used for simple redaction with ***
    #    - Example: "user42" -> "user73" (random each time)
    #
    # 2. Pseudonymization mode (pseudonymization enabled):
    #    - Generates consistent deterministic mappings
    #    - Same input always produces same output
    #    - Example: "user42" -> "user17" (always the same)
    #    - Warns if pattern has too few possible values (<100 recommended)
    #
    # ============================================================================
    # IMPORTANT: Special placeholders
    # ============================================================================
    #
    # Special placeholders are automatically replaced with realistic data:
    #   {users}  - Realistic user folder names (alice, bob, charlie, diana, etc.)
    #   {emails} - Realistic email addresses (alice.smith@example.com, etc.)
    #   {names}  - Realistic usernames (alice.smith, bob.jones, etc.)
    #
    # These placeholders are replaced with equivalent regex patterns before
    # regex generation, so they work seamlessly with any regex pattern.
    #
    # YAML ESCAPING RULES (for regex special characters):
    # In YAML strings, backslash is an escape character, so:
    #   - To match a literal dot (.):     use \\. in YAML (becomes \. in regex)
    #   - To match a literal backslash:   use \\\\ in YAML (becomes \\ in regex)
    #
    # EXAMPLES:
    #   Unix home with placeholder:
    #     "/home/{users}"               → generates "/home/alice"
    #
    #   Windows home with placeholder:
    #     "C:\\\\Users\\\\{users}"      → generates "C:\Users\alice"
    #     Note: \\\\ in YAML becomes \\ in regex (matches single backslash)
    #
    #   Email domain:
    #     "[a-z]+@example\\.com"        → generates "user@example.com"
    #     (\\. becomes \. in regex, matches literal dot)
    #
    #   IP addresses:
    #     "10\\.0\\.[0-9]{1,3}\\.[0-9]{1,3}"  → generates "10.0.123.45"
    #
    #   Mixed path and placeholder:
    #     "/data/{users}/files"         → generates "/data/bob/files"
    #
    #   Multiple placeholders:
    #     "/home/{users} owned by {names}"  → generates "/home/alice owned by bob.smith"
    #
    #   Server logs with pattern and placeholder:
    #     "srv[0-9]{2}/{users}/app\\.log"   → generates "srv42/charlie/app.log"
    #
    # ============================================================================
    pattern_generators:
    # SSH host patterns - generates hostnames matching the regex
    # "ssh_hosts": "host[0-9]{2}\\.example\\.com"

    # IP address patterns - generates IP addresses in specific ranges
    # "ip_addresses": "10\\.0\\.[0-9]{1,3}\\.[0-9]{1,3}"
    # "ipv4_private": "192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}"

    # Username patterns - generates consistent usernames
    # "usernames": "user[0-9]{3}"
    # "service_accounts": "svc_[a-z]{4}[0-9]{2}"

    # User path patterns with {users} placeholder
    # "unix_home": "/home/{users}"
    # "mac_home": "/Users/{users}"
    # "win_home": "C:\\\\Users\\\\{users}"

    # Temporary file patterns
    # "temp_files": "temp_[a-z0-9]{8}"
    # "session_ids": "[a-f0-9]{32}"

    # Email patterns with placeholder
    # "user_emails": "{emails}"
    # "internal_emails": "[a-z]{5}\\.[a-z]{5}@internal\\.example\\.com"

    # Custom application-specific patterns
    # "app_tokens": "tok_[A-Za-z0-9]{16}"
    # "customer_ids": "CUST[0-9]{8}"

# Usage examples:
#
# Use this custom config:
#   java -jar jfr-redact.jar input.jfr output.jfr --config my-config.yaml
#
# Start with a preset and override:
#   java -jar jfr-redact.jar input.jfr output.jfr --preset strict --keep-local-addresses
#
# Enable pseudonymization to preserve relationships:
#   java -jar jfr-redact.jar input.jfr output.jfr --config my-config.yaml --pseudonymize
#
# Use pseudonymization with custom format:
#   java -jar jfr-redact.jar input.jfr output.jfr --pseudonymize --pseudonym-format hash
#
# Test without creating output:
#   java -jar jfr-redact.jar input.jfr output.jfr --config my-config.yaml --dry-run --verbose
```

Development
-----------

To preview changes without modifying files:
```bash
./sync-documentation.py --dry-run
```

To install as a git pre-commit hook (auto-syncs on commit):
```bash
./sync-documentation.py --install
```

### Publishing to Maven Central

For maintainers publishing to Maven Central, use the `bin/update_gh_secrets.sh` script to configure GitHub Actions secrets:

```bash
./bin/update_gh_secrets.sh
```

This script:
- Reads Maven credentials from `~/.m2/settings.xml` (or prompts for them)
- Exports your GPG private key
- Updates GitHub repository secrets required for Maven Central deployment:
  - `MAVEN_USERNAME` and `MAVEN_PASSWORD` (OSSRH credentials)
  - `GPG_KEYNAME`, `GPG_PASSPHRASE`, and `GPG_PRIVATE_KEY`

Requires: [GitHub CLI (gh)](https://cli.github.com/)

### Git Hooks Setup

The `bin/sync-documentation.py` script keeps documentation in sync and can install a pre-commit hook:

```bash
# Install pre-commit hook (runs tests and syncs docs on every commit)
./bin/sync-documentation.py --install

# Manually sync documentation
./bin/sync-documentation.py

# Preview changes without modifying files
./bin/sync-documentation.py --dry-run
```

The pre-commit hook will:
1. Run `mvn test` to ensure all tests pass
2. Sync version from `Version.java` to `pom.xml`
3. Update README.md with latest configuration examples

To skip the hook temporarily: `git commit --no-verify`

### Deployment

To release a new version to Maven Central:

1. Update the version in `src/main/java/me/bechberger/jfr-redact/Version.java`
2. Run `./bin/sync-documentation.py` to sync version to `pom.xml`
3. Commit the changes
4. Create and push a tag: `git tag v<version> && git push origin v<version>`
5. The CI will automatically build, sign, and deploy to Maven Central

The `publish-maven.yml` workflow handles GPG signing and deployment to OSSRH.

### IDE Support for Configuration Files

The project automatically generates a JSON Schema (`config-schema.json`) during build, enabling autocomplete and validation for YAML configuration files.

**Getting the Schema:**
- Build locally: `mvn package && java -jar target/jfr-redact.jar generate-schema config-schema.json`
- Download from CI: Check the [Actions tab](https://github.com/parttimenerd/jfr-redact/actions) and download the `config-schema` artifact from recent builds

**VS Code**: The schema reference is already included in config files:
```yaml
# yaml-language-server: $schema=./config-schema.json
```
You'll get autocomplete and validation automatically when editing config files.

**IntelliJ IDEA**: The schema reference should work automatically. To configure manually:
- Go to Settings → Languages & Frameworks → Schemas and DTDs → JSON Schema Mappings
- Add mapping for `*.yaml` files to `config-schema.json`

Support, Feedback, Contributing
-------------------------------
This project is open to feature requests/suggestions, bug reports etc. 
via [GitHub](https://github.com/parttimenerd/jfr-redact/issues) issues. 
Contribution and feedback are encouraged and always welcome. 
For more information about how to contribute, the project structure, 
as well as additional contribution information, see our Contribution Guidelines.


License
-------
MIT, Copyright 2025 SAP SE or an SAP affiliate company, Johannes Bechberger and contributors