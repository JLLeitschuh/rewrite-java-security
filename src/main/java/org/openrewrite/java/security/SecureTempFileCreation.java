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
package org.openrewrite.java.security;

import lombok.AllArgsConstructor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Option;
import org.openrewrite.Recipe;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.J;

import java.nio.file.PathMatcher;
import java.time.Duration;

@AllArgsConstructor
public class SecureTempFileCreation extends Recipe {

    @AllArgsConstructor
    enum Target {
        AllSource(Target.ALL_SOURCE),
        AllSourceWhenNonTestDetected(Target.ALL_SOURCE_IF_DETECTED),
        NonTestSource(Target.NON_TEST_SOURCE);

        static final String ALL_SOURCE = "All Source";
        static final String ALL_SOURCE_IF_DETECTED = "All Source if detected in Non Test Source";
        static final String NON_TEST_SOURCE = "Non-Test Source";

        private static Target fromString(String target) {
            switch (target) {
                case ALL_SOURCE:
                    return AllSource;
                case ALL_SOURCE_IF_DETECTED:
                    return AllSourceWhenNonTestDetected;
                case NON_TEST_SOURCE:
                    return NonTestSource;
                default:
                    @SuppressWarnings("ConstantConditions")
                    String targetDescription = target == null ? "`null`" : target.isEmpty() ? "`empty`" : target;
                    throw new IllegalArgumentException("Unknown target: " + targetDescription);
            }
        }

        private final String description;
    }

    @Option(
            displayName = "Target",
            valid = {
                    Target.ALL_SOURCE,
                    Target.ALL_SOURCE_IF_DETECTED,
                    Target.NON_TEST_SOURCE
            },
            example = Target.ALL_SOURCE
    )
    private final String target;

    @Override
    public String getDisplayName() {
        return "Use secure temporary file creation";
    }

    @Override
    public String getDescription() {
        return "`java.io.File.createTempFile()` has exploitable default file permissions. This recipe migrates to the more secure `java.nio.file.Files.createTempFile()`.";
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(5);
    }

    @Override
    protected JavaIsoVisitor<ExecutionContext> getSingleSourceApplicableTest() {
        return new UsesMethod<>(SecureTempFileCreationVisitor.MATCHER);
    }

    @Override
    protected JavaIsoVisitor<ExecutionContext> getVisitor() {
        Target target = Target.fromString(this.target);
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.CompilationUnit visitCompilationUnit(J.CompilationUnit cu, ExecutionContext executionContext) {
                PathMatcher testMatcher = cu.getSourcePath().getFileSystem().getPathMatcher("glob:**/test/**");
                // If the target is Non Test Source, and this is a test source file, skip it.
                if ((target == Target.NonTestSource || target == Target.AllSourceWhenNonTestDetected) && testMatcher.matches(cu.getSourcePath())) {
                    return cu;
                }
                J.CompilationUnit compilationUnit = (J.CompilationUnit) new SecureTempFileCreationVisitor().visitNonNull(cu, executionContext, getCursor().getParentOrThrow());
                if (target == Target.AllSourceWhenNonTestDetected && compilationUnit != cu) {
                    // A non-test source file was changed, so we should change all source files.
                    if (getRecipeList().stream().noneMatch(SecureTempFileCreation.class::isInstance)) {
                        getRecipeList().add(new SecureTempFileCreation(Target.ALL_SOURCE));
                    }
                }
                return compilationUnit;
            }
        };
    }
}
