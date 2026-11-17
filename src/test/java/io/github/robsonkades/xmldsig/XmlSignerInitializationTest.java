package io.github.robsonkades.xmldsig;

import org.apache.xml.security.Init;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Timeout(25)
class XmlSignerInitializationTest {

    private static final String IGNORE_LINE_BREAKS = "org.apache.xml.security.ignoreLineBreaks";

    @TempDir
    Path temporaryDirectory;

    @Test
    void firstUseConfiguresSantuarioInFreshJvm() throws Exception {
        ProcessResult result = launch(List.of(), "signer-first");

        assertEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("INITIALIZATION_OK ignoreLineBreaks=true"), result.output());
    }

    @Test
    void earlierSantuarioInitializationWithLineBreaksFailsClearly() throws Exception {
        // XMLUtils caches its default false before XmlSigner can set the property to true.
        ProcessResult result = launch(List.of(), "santuario-first");

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains("SANTUARIO_INITIALIZED ignoreLineBreaks=false"), result.output());
        assertTrue(result.output().contains("ExceptionInInitializerError"), result.output());
        assertTrue(result.output().contains("IllegalStateException: Apache Santuario was initialized"), result.output());
        assertTrue(result.output().contains("-D" + IGNORE_LINE_BREAKS + "=true"), result.output());
        assertFalse(result.output().contains("INITIALIZATION_OK"), result.output());
    }

    @Test
    void startupFlagAllowsSantuarioToInitializeFirst() throws Exception {
        ProcessResult result = launch(List.of("-D" + IGNORE_LINE_BREAKS + "=true"), "santuario-first");

        assertEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("SANTUARIO_INITIALIZED ignoreLineBreaks=true"), result.output());
        assertTrue(result.output().contains("INITIALIZATION_OK ignoreLineBreaks=true"), result.output());
    }

    private ProcessResult launch(List<String> jvmArguments, String order) throws Exception {
        String executable = System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java";
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", executable).toString());
        command.addAll(jvmArguments);
        command.add("-cp");
        command.add(classpath);
        command.add(InitializationProbe.class.getName());
        command.add(order);

        Path outputFile = Files.createTempFile(temporaryDirectory, "initialization-", ".log");
        ProcessBuilder builder = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(outputFile.toFile());
        // Keep each child's startup scenario independent of ambient JVM injection options.
        builder.environment().remove("JAVA_TOOL_OPTIONS");
        builder.environment().remove("JDK_JAVA_OPTIONS");
        builder.environment().remove("_JAVA_OPTIONS");
        Process process = builder.start();
        try {
            process.getOutputStream().close();
            if (!process.waitFor(15, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "Child JVM did not terminate");
                fail("Child JVM timed out: " + Files.readString(outputFile, StandardCharsets.UTF_8));
            }
            return new ProcessResult(process.exitValue(), Files.readString(outputFile, StandardCharsets.UTF_8));
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "Child JVM did not terminate during cleanup");
            }
        }
    }

    private record ProcessResult(int exitCode, String output) {
    }

    /** Entry point used only in subprocesses so class initialization never depends on test order. */
    public static final class InitializationProbe {

        public static void main(String[] arguments) {
            switch (arguments[0]) {
                case "signer-first" -> {
                    if (System.getProperty(IGNORE_LINE_BREAKS) != null) {
                        throw new AssertionError("Expected the library to configure the absent property");
                    }
                }
                case "santuario-first" -> {
                    boolean ignoreLineBreaks = XMLUtils.ignoreLineBreaks();
                    Init.init();
                    System.out.println("SANTUARIO_INITIALIZED ignoreLineBreaks=" + ignoreLineBreaks);
                }
                default -> throw new AssertionError("Unknown initialization order");
            }

            VerificationResult result = XmlSigner.verifyIntegrity("<root/>");
            if (result.valid() || !"No Signature element found".equals(result.detail())) {
                throw new AssertionError("Expected unsigned XML to be rejected after successful initialization");
            }
            if (!XMLUtils.ignoreLineBreaks()) {
                throw new AssertionError("Santuario line-break setting was not enabled");
            }
            System.out.println("INITIALIZATION_OK ignoreLineBreaks=" + XMLUtils.ignoreLineBreaks());
        }
    }
}
