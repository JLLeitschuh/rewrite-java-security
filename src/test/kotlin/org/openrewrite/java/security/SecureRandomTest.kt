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
import org.openrewrite.java.JavaParser
import org.openrewrite.java.JavaRecipeTest

class SecureRandomTest : JavaRecipeTest {
    override val recipe: Recipe
        get() = SecureRandom()

    @Test
    fun secureContext() = assertChanged(
        before = """
            import java.util.Random;
            
            public class A {
                String generateSecretToken() {
                    Random r = new Random();
                    return Long.toHexString(r.nextLong());
                }
            }
        """,
        after = """
            import java.security.SecureRandom;
            import java.util.Random;
            
            public class A {
                String generateSecretToken() {
                    Random r = new SecureRandom();
                    return Long.toHexString(r.nextLong());
                }
            }
        """
    )
}
