/*
 * Copyright 2021 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.openrewrite.java.security

import org.junit.jupiter.api.Test
import org.openrewrite.Recipe
import org.openrewrite.java.JavaRecipeTest

class SecureTempFileCreationTest : JavaRecipeTest {


    override val recipe: Recipe
        get() = SecureTempFileCreation()

    @Test
    fun twoArgCreateTempFile() = assertChanged(
        before = """
            import java.io.File;
            import java.io.IOException;

            class Test {
                static void method() throws IOException {
                    File tempDir = File.createTempFile("hello", "world");
                }
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;

            class Test {
                static void method() throws IOException {
                    File tempDir = Files.createTempFile("hello", "world").toFile();
                }
            }
        """
    )

    @Test
    fun threeArgCreateTempFile() = assertChanged(
        before = """
            import java.io.File;
            import java.io.IOException;

            class Test {
                static void method() throws IOException {
                    File tempDir = File.createTempFile("hello", "world", new File("."));
                }
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;

            class Test {
                static void method() throws IOException {
                    File tempDir = Files.createTempFile(new File(".").toPath(), "hello", "world").toFile();
                }
            }
        """
    )

    @Test
    fun threeArgWithNullPath() =  assertChanged(
        before = """
            import java.io.File;
            
            class T {
                File temp = File.createTempFile("random", "file", null);
            }
        """,
        after = """
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                File temp = Files.createTempFile("random", "file").toFile();
            }
        """
    )

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

            class T {
                void vulnerableFileCreateTempFilesNewBufferedWriter()  throws IOException  {
                    Path tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-buffered-writer.txt").toPath();
                    Files.createFile(tempDirChild, PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                    BufferedWriter bw = Files.newBufferedWriter(tempDirChild);
                }
            }
        """
    )

}
