# Hardened FIPS Java Buildpack

This buildpack provides a highly secure Java Runtime Environment (JRE) designed for environments requiring FIPS 140-3 compliance. It integrates BouncyCastle FIPS cryptographic modules and enforces strict security policies while maintaining enterprise-grade observability and performance tuning.

## Target Audience
This solution is intended for security-sensitive sectors, including:
*   Banking and Financial Institutions.
*   Government and Defense Agencies.
*   Organizations undergoing strict regulatory security audits.

---

## Supported Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `BP_JVM_TYPE`| JRE or JDK | --- |
| `BP_JVM_VERSION` | java version | 21 |
| `BPL_JVM_HEAD_ROOM` | Percentage of memory to leave as headroom for the OS (0-100). | `25` |
| `BPL_JAVA_NMT_ENABLED` | Enables Native Memory Tracking (NMT). | `true` |
| `BPL_JAVA_NMT_LEVEL` | Detail level for NMT output (`summary` or `detail`). | `summary` |
| `BPL_JMX_ENABLED` | Enables remote JMX monitoring. | `false` |
| `BPL_JMX_PORT` | Port for JMX monitoring. | `5000` |
| `BPL_DEBUG_ENABLED` | Enables remote debugging support. | `false` |
| `BPL_DEBUG_PORT` | Port for remote debugging. | `8000` |
| `BPL_DEBUG_SUSPEND` | Whether the JVM should wait for a debugger to attach. | `false` |
| `BPL_JFR_ENABLED` | Enables Java Flight Recording (JFR). | `false` |
| `BPL_HEAP_DUMP_PATH` | Path to write heap dumps on OutOfMemoryError. | (Disabled) |

---

## Built-in Optimizations and Hardening
The buildpack automatically configures the following low-level settings for container stability:
*   **FIPS Enforcement:** Enforces BouncyCastle FIPS as the primary provider and disables non-approved cryptographic algorithms.
*   **Memory Arena Management:** Sets `MALLOC_ARENA_MAX=2` to reduce memory fragmentation and prevent excessive virtual memory growth in containers.
*   **DNS TTL Fix:** Sets the network address cache TTL to 60 seconds to ensure the JVM respects DNS changes in dynamic environments like Kubernetes.
*   **Encoding:** Forces `UTF-8` file encoding globally.

---

## Comparison with Paketo (BellSoft Liberica)

### Missing Features
While this buildpack offers advanced security hardening, the following features available in the standard Paketo BellSoft Liberica buildpack are not supported:

1.  **External Memory Calculator:** Unlike Paketo, which uses an external Go-based binary to calculate memory limits, this buildpack relies on native JVM container support (`MaxRAMPercentage`). This is simpler but lacks the granular thread/class-based calculation of the Paketo tool.
2.  **Jlink Support:** This buildpack does not support the `jlink` tool for creating custom, minified JRE distributions at build time.

### GraalVM Support
*   **No GraalVM / Native Image:** This buildpack does not include GraalVM or support for compiling applications into Native Images. It is strictly optimized for standard JRE/JDK execution with FIPS compliance.
