package org.openrewrite.java.security

import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.openrewrite.java.JavaRecipeTest

class PreventTempDirectoryHijackingTest : JavaRecipeTest {

    @Disabled
    @Suppress("UnnecessaryLocalVariable")
    @Test
    fun createTempDirFromFile() = assertChanged(
        before = """
            import java.io.File;
            import java.io.IOException;
            import java.util.UUID;
            
            class T {
                void doSomething() throws IOException {
                    File tmpdir = File.createTempFile("bookie" + UUID.randomUUID() + "_", "test");
                    if (!tmpdir.delete()) {
                        System.out.println("Fail to delete tmpdir " + tmpdir);
                    }
                    if (!tmpdir.mkdir()) {
                        throw new IOException("Fail to create tmpdir " + tmpdir);
                    }
                }
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.util.UUID;
            
            class T {
                void doSomething() throws IOException {
                    File tmpdir = Files.createTempDirectory("bookie" + UUID.randomUUID() + "_" + "test").toFile();
                    return tmpdir;
                }
            }
        """
    )

    @Suppress("ResultOfMethodCallIgnored", "UnnecessaryLocalVariable")
    @Disabled
    @Test
    fun createTempDirFromFile2() = assertChanged(
        before = """
            import java.io.File;
            import java.io.IOException;
            import java.util.UUID;
            
            class T {
                File createTempFile(String prefix, String suffix, File directory) throws IOException {
                    File dir = File.createTempFile(prefix, suffix, directory);
                    dir.delete();
                    if (dir.mkdir()) {
                        return dir;
                    } else {
                        throw IOException("Unable to create temporary directory " + directory);
                    }
                }
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.util.UUID;
            
            class T {
                File createTempFile(String prefix, String suffix, File directory) throws IOException {
                    File dir = Files.createTempDirectory(directory.toPath(), prefix + suffix).toFile();
                    return dir;
                }
            }
        """
    )

    @Test
    fun vulnerableFileCreateTempFile() = assertChanged(
        before = """
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFile() {
                    File tempFile = File.createTempFile("random", "file");
                }
            }
        """,
        after = """
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateTempFile() {
                    File tempFile = Files.createTempFile("random", "file").toFile();
                }
            }
        """
    )

    @Test
    fun vulnerableFileCreateTempFileNull() = assertChanged(
        before = """
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFileNull() {
                    File tempFile = File.createTempFile("random", "file", null);
                }
            }
        """,
        after = """
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateTempFileNull() {
                    File tempFile = Files.createTempFile("random", "file").toFile();
                }
            }
        """
    )

    @Test
    fun vulnerableFileCreateTempFileTainted() = assertChanged(
        before = """
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFileTainted() {
                    File tempDir = new File(System.getProperty("java.io.tmpdir"));
                    File tempVuln = File.createTempFile("random", "file", tempDir);
                    // TO MAKE SAFE REWRITE TO (v2):
                    // File tempSafe2 = Files.createTempFile("random", "file").toFile();
                }
            }
        """,
        after = """
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateTempFileTainted() {
                    File tempDir = new File(System.getProperty("java.io.tmpdir"));
                    File tempVuln = Files.createTempFile(tempDir.toPath(), "random", "file").toFile();
                    // TO MAKE SAFE REWRITE TO (v2):
                    // File tempSafe2 = Files.createTempFile("random", "file").toFile();
                }
            }
        """
    )

    @Test
    fun vulnerableFileCreateTempFileChildTainted() = assertChanged(
        before = """
            import java.io.File;
            import java.io.IOException;
            
            class T {
                void vulnerableFileCreateTempFileChildTainted() throws IOException {
                    File tempDirChild = new File(new File(System.getProperty("java.io.tmpdir")), "/child");
                    File tempFile = File.createTempFile("random", "file", tempDirChild);
                }
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateTempFileChildTainted() throws IOException {
                    File tempDirChild = new File(new File(System.getProperty("java.io.tmpdir")), "/child");
                    File tempFile = Files.createTempFile(tempDirChild.toPath(), "random", "file").toFile();
                }
            }
        """
    )

    @Test
    fun vulnerableFileCreateTempFileCanonical() = assertChanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFileCanonical() throws IOException {
                    File tempDir = new File(System.getProperty("java.io.tmpdir")).getCanonicalFile();
                    File tempFile = File.createTempFile("random", "file", tempDir);
                    
                    // TO MAKE SAFE REWRITE TO (v2):
                    // File tempSafe2 = Files.createTempFile("random", "file").toFile();
                }
            }
        """,
        after = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateTempFileCanonical() throws IOException {
                    File tempDir = new File(System.getProperty("java.io.tmpdir")).getCanonicalFile();
                    File tempFile = Files.createTempFile(tempDir.toPath(), "random", "file").toFile();
                    
                    // TO MAKE SAFE REWRITE TO (v2):
                    // File tempSafe2 = Files.createTempFile("random", "file").toFile();
                }
            }
        """
    )

    @Test
    fun vulnerableFileCreateTempFileAbsolute() = assertChanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFileAbsolute() throws IOException {
                    File tempDir = new File(System.getProperty("java.io.tmpdir")).getAbsoluteFile();
                    File tempFile = File.createTempFile("random", "file", tempDir);
                    
                    // TO MAKE SAFE REWRITE TO (v2):
                    // File tempSafe2 = Files.createTempFile("random", "file").toFile();
                }
            }
        """,
        after = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateTempFileAbsolute() throws IOException {
                    File tempDir = new File(System.getProperty("java.io.tmpdir")).getAbsoluteFile();
                    File tempFile = Files.createTempFile(tempDir.toPath(), "random", "file").toFile();
                    
                    // TO MAKE SAFE REWRITE TO (v2):
                    // File tempSafe2 = Files.createTempFile("random", "file").toFile();
                }
            }
        """
    )

    @Disabled
    @Test
    fun safeFileCreateTempFileTainted() = assertUnchanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            
            class T {
                void safeFileCreateTempFileTainted() throws IOException {
                    /*
                     * Creating a temporary directoy in the current user directory is not a
                     * vulnerability.
                     */
                    File currentDirectory = new File(System.getProperty("user.dir"));
                    File temp = File.createTempFile("random", "file", currentDirectory);
                }
            }
        """
    )

    @Suppress("deprecation", "UnstableApiUsage")
    @Disabled
    @Test
    fun vulnerableGuavaFilesCreateTempDir() = assertChanged(
        before = """
            import java.io.File;
            
            class T {
                File vulnerableGuavaFilesCreateTempDir() {
                    return com.google.common.io.Files.createTempDir();
                }
            }
        """,
        after = """
            import java.io.File;
            import java.nio.file.Files;
            import java.io.IOException;
            import java.io.UncheckedIOException;
            
            class T {
                File vulnerableGuavaFilesCreateTempDir() {
                    File tempDir;
                    try {
                        return Files.createTempDirectory("random").toFile();
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }
            }
        """
    )

    @Suppress("ResultOfMethodCallIgnored", "RedundantThrows")
    @Test
    fun vulnerableFileCreateTempFileMkdirTainted() = assertChanged(
        before = """
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFileMkdirTainted() throws Exception {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                    tempDirChild.mkdir();
                }
            }
        """,
        after = """
            import java.io.File;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.UUID;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFileMkdirTainted() throws Exception {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                    Files.createTempDirectory(
                        tempDirChild.toPath(), 
                        UUID.randomUUID().toString(),
                        PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)))
                        .toFile();
                }
            }
        """
    )

    @Suppress("ResultOfMethodCallIgnored")
    @Disabled
    @Test
    fun vulnerableFileCreateTempFileMkdirsTainted() = assertChanged(
        before = """
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFileMkdirsTainted() {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                    tempDirChild.mkdirs();
                }
                
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.io.UncheckedIOException;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.UUID;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFileMkdirsTainted() {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                    try {
                        Files.createTempDirectory(
                            tempDirChild.toPath(),
                            UUID.randomUUID().toString(), 
                            PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
                        ).toFile();
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }
                
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateTempFilesWrite1() = assertChanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.charset.StandardCharsets;
            import java.nio.file.Files;
            import java.nio.file.StandardOpenOption;
            import java.util.Collections;
            
            class T {
                void vulnerableFileCreateTempFilesWrite1() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child.txt");
                    Files.write(tempDirChild.toPath(), Collections.singletonList("secret"), StandardCharsets.UTF_8, StandardOpenOption.CREATE);
                }
            }
        """,
        after = """
            import java.io.IOException;
            import java.io.File;
            import java.io.UncheckedIOException;
            import java.nio.charset.StandardCharsets;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.nio.file.StandardOpenOption;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.nio.file.attribute.PosixFilePermission;
            import java.util.Collections;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFilesWrite1() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child.txt");
                    Files.createFile(tempDirChild.toPath(), PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                    Files.write(tempDirChild, Collections.singletonList("secret"));
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateTempFilesWrite2() = assertChanged(
        before = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.nio.file.StandardOpenOption;
            
            class T {
                void vulnerableFileCreateTempFilesWrite2() throws IOException {
                    String secret = "secret";
                    byte[] byteArray = secret.getBytes();
                    
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child.txt");
                    Files.write(tempDirChild.toPath(), byteArray, StandardOpenOption.CREATE);
                }
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.nio.file.StandardOpenOption;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFilesWrite2() throws IOException {
                    String secret = "secret";
                    byte[] byteArray = secret.getBytes();
                    
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child.txt");
                    Files.createFile(tempDirChild.toPath(), PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                    Files.write(tempDirChild, byteArray);
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateTempFilesNewBufferedWriter() = assertChanged(
        before = """
            import java.io.BufferedWriter;
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateTempFilesNewBufferedWriter() throws IOException {
                    Path tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-buffered-writer.txt").toPath();
                    BufferedWriter bw = Files.newBufferedWriter(tempDirChild);
                }
            }
        """,
        after = """
            import java.io.BufferedWriter;
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            class T {
                void vulnerableFileCreateTempFilesNewBufferedWriter()  throws IOException  {
                    Path tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-buffered-writer.txt").toPath();
                    Files.createFile(tempDirChild, PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                    BufferedWriter bw = Files.newBufferedWriter(tempDirChild);
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateTempFilesNewOutputStream() = assertChanged(
        before = """
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFilesNewOutputStream() {
                    Path tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-output-stream.txt").toPath();
                    Files.newOutputStream(tempDirChild).close();
                }
            }
        """,
        after = """
            import java.io.File;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFilesNewOutputStream() {
                    Path tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-output-stream.txt").toPath();
                    Files.createFile(tempDirChild, PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                    Files.newOutputStream(tempDirChild).close();
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateTempFilesCreateFile() = assertChanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateTempFilesCreateFile() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-file.txt");
                    Files.createFile(tempDirChild.toPath());
                }
            }
        """,
        after = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            
            class T {
                void vulnerableFileCreateTempFilesCreateFile() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-file.txt");
                    Files.createFile(tempDirChild.toPath(), PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                }
            }
        """
    )

    @Test
    fun safeFileCreateTempFilesCreateFile() = assertUnchanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void safeFileCreateTempFilesCreateFile() throws IOException {
                    // Clear permissions intentions by setting the 'OWNER_READ' and 'OWNER_WRITE'
                    // permissions.
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-file.txt");
                    Files.createFile(tempDirChild.toPath(), PosixFilePermissions.asFileAttribute(
                        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
                    );
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateDirectory() = assertChanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateDirectory() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-directory");
                    Files.createDirectory(tempDirChild.toPath());
                }
            }
        """,
        after = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateDirectory() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-directory");
                    Files.createDirectory(tempDirChild.toPath(), PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateDirectories() = assertChanged(
        before = """
            import java.io.File;
            import java.nio.file.Files;
            import java.io.IOException;
            
            class T {
                void vulnerableFileCreateDirectories() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-directories/child");
                    Files.createDirectories(tempDirChild.toPath());
                }
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateDirectories() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-directories/child");
                    Files.createDirectories(tempDirChild.toPath(), PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                }
            }
        """
    )
}