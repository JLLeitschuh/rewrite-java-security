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
import lombok.NoArgsConstructor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.Tree;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.cleanup.SimplifyCompoundVisitor;
import org.openrewrite.java.cleanup.SimplifyConstantIfBranchExecution;
import org.openrewrite.java.marker.JavaVersion;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.*;
import org.openrewrite.marker.Markers;

import java.io.File;
import java.time.Duration;
import java.util.*;

public class UseFilesCreateTempDirectory extends Recipe {

    private static final MethodMatcher CREATE_TEMP_FILE_MATCHER = new MethodMatcher("java.io.File createTempFile(..)");

    @Override
    public String getDisplayName() {
        return "Use Files#createTempDirectory";
    }

    @Override
    public String getDescription() {
        return "Use `Files#createTempDirectory` when the sequence `File#createTempFile(..)`->`File#delete()`->`File#mkdir()` is used for creating a temp directory.";
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("RSPEC-5445");
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(10);
    }

    @Override
    protected JavaVisitor<ExecutionContext> getSingleSourceApplicableTest() {
        return new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitJavaSourceFile(JavaSourceFile cu, ExecutionContext executionContext) {
                doAfterVisit(new UsesMethod<>("java.io.File createTempFile(..)"));
                doAfterVisit(new UsesMethod<>("java.io.File mkdir(..)"));
                doAfterVisit(new UsesMethod<>("java.io.File mkdirs(..)"));
                return cu;
            }
        };
    }

    @Override
    public JavaIsoVisitor<ExecutionContext> getVisitor() {
        return new UsesFilesCreateTempDirVisitor();
    }

    private static class UsesFilesCreateTempDirVisitor extends JavaIsoVisitor<ExecutionContext> {
        private static final MethodMatcher DELETE_MATCHER = new MethodMatcher("java.io.File delete()");
        private static final MethodMatcher MKDIR_MATCHER = new MethodMatcher("java.io.File mkdir()");
        private static final MethodMatcher MKDIRS_MATCHER = new MethodMatcher("java.io.File mkdirs()");

        @Override
        public JavaSourceFile visitJavaSourceFile(JavaSourceFile cu, ExecutionContext executionContext) {
            Optional<JavaVersion> javaVersion = cu.getMarkers().findFirst(JavaVersion.class);
            if (javaVersion.isPresent() && javaVersion.get().getMajorVersion() < 7) {
                return cu;
            }
            return super.visitJavaSourceFile(cu, executionContext);
        }

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
            J.MethodInvocation mi = super.visitMethodInvocation(method, executionContext);
            if (CREATE_TEMP_FILE_MATCHER.matches(mi)) {
                J.Block block = getCursor().firstEnclosing(J.Block.class);
                if (block != null) {
                    J createFileStatement = null;
                    J firstParent = getCursor().dropParentUntil(J.class::isInstance).getValue();
                    if (firstParent instanceof J.Assignment && ((J.Assignment) firstParent).getVariable() instanceof J.Identifier) {
                        createFileStatement = firstParent;
                    }
                    if (createFileStatement == null && firstParent instanceof J.VariableDeclarations.NamedVariable) {
                        createFileStatement = firstParent;
                    }
                    if (createFileStatement != null) {
                        getCursor().dropParentUntil(J.Block.class::isInstance)
                                .computeMessageIfAbsent("CREATE_FILE_STATEMENT", v -> new ArrayList<>()).add(createFileStatement);
                    }
                }
            }
            return mi;
        }

        @NoArgsConstructor
        private static class TempDirHijackingChainStateMachine {
            private enum State {
                /**
                 * The initial state, no calls have been observed.
                 */
                INIT,
                /**
                 * A call to {@link File#createTempFile} has been observed.
                 */
                CREATE,
                /**
                 * A call to {@link File#delete()} has been observed.
                 */
                DELETE,
                /**
                 * A call to {@link File#mkdir()} or {@link File#mkdirs()} has been observed.
                 */
                MKDIR
            }
            private State state = State.INIT;
            private final Map<String, Statement> stmtMap = new HashMap<>(4);

            void stateCreateStatement(Statement insecureCreateStatement, Statement secureCreateStatement) {
                if (state.equals(State.INIT)) {
                    stmtMap.put("create", insecureCreateStatement);
                    stmtMap.put("secureCreate", secureCreateStatement);
                    state = State.CREATE;
                }
            }

            void stateDeleteStatement(Statement deleteStatement) {
                if (state.equals(State.CREATE)) {
                    stmtMap.put("delete", deleteStatement);
                    state = State.DELETE;
                }
            }

            void stateMkdirStatement(Statement mkdirStatement) {
                if (state.equals(State.DELETE)) {
                    stmtMap.put("mkdir", mkdirStatement);
                    state = State.MKDIR;
                }
            }

            /**
             * The variable that we're tracking through the state machine has been reassigned to a different value.
             */
            public void stateVariableReassigned() {
                if (!state.equals(State.MKDIR)) {
                    state = State.INIT;
                }
            }

            boolean isStateMachineSatisfied() {
                return state.equals(State.MKDIR);
            }

            Statement getCreateStatement() {
                assert isStateMachineSatisfied() : "State machine is not in correct 'final' state.";
                return stmtMap.get("create");
            }

            Statement getSecureCreateStatement() {
                assert isStateMachineSatisfied() : "State machine is not in correct 'final' state.";
                return stmtMap.get("secureCreate");
            }

            Statement getDeleteStatement() {
                assert isStateMachineSatisfied() : "State machine is not in correct 'final' state.";
                return stmtMap.get("delete");
            }

            Statement getMkdirStatement() {
                assert isStateMachineSatisfied() : "State machine is not in correct 'final' state.";
                return stmtMap.get("mkdir");
            }
        }

        @AllArgsConstructor
        private static class TempDirHijackingChainFinderVisitor extends JavaIsoVisitor<TempDirHijackingChainStateMachine> {
            private final J createFileStatement;

            @Override
            public Statement visitStatement(Statement stmt, TempDirHijackingChainStateMachine stateMachine) {
                Statement s = super.visitStatement(stmt, stateMachine);
                J.Identifier createFileIdentifier = getIdent(createFileStatement);
                if (createFileIdentifier != null) {
                    if (isMatchingCreateFileStatement(createFileStatement, stmt)) {
                        stateMachine.stateCreateStatement(
                                stmt,
                                (Statement) new SecureTempDirectoryCreation<>()
                                        .visitNonNull(stmt, stateMachine, getCursor().getParentOrThrow())
                        );
                    } else if (isMethodForIdent(createFileIdentifier, DELETE_MATCHER, stmt)) {
                        stateMachine.stateDeleteStatement(stmt);
                    } else if (isMethodForIdent(createFileIdentifier, MKDIR_MATCHER, stmt)
                            || isMethodForIdent(createFileIdentifier, MKDIRS_MATCHER, stmt)) {
                        stateMachine.stateMkdirStatement(stmt);
                    } else if (isAssignmentForIdent(createFileIdentifier, stmt)) {
                        stateMachine.stateVariableReassigned();
                    }
                }
                return s;
            }
        }

        private static class ReplaceStatement<P> extends JavaVisitor<P> {
            private final Statement statement;
            private final Expression replacement;

            public ReplaceStatement(Statement statement, Expression replacement) {
                this.statement = statement;
                this.replacement = replacement;
            }

            @Override
            public J visitExpression(Expression expression, P p) {
                // The statement should only be replaced when removing would cause invalid code.
                if (expression == statement &&
                        // If the direct parent of this expression is a `J.Block` then it should be removed by `DeleteStatementNonIso`.
                        !(getCursor().getParentOrThrow(2).getValue() instanceof J.Block)) {
                    return replacement;
                }
                return super.visitExpression(expression, p);
            }
        }

        private J.Block deleteOrReplaceStatement(J.Block bl, Statement stmt, Expression replacement, ExecutionContext executionContext) {
            bl = (J.Block) new DeleteStatement<>(stmt)
                    .visitNonNull(bl, executionContext, getCursor().getParentOrThrow());
            bl = (J.Block) new ReplaceStatement<>(
                    stmt,
                    replacement
            ).visitNonNull(bl, executionContext, getCursor().getParentOrThrow());
            return bl;
        }

        @Override
        public J.Block visitBlock(J.Block block, ExecutionContext executionContext) {
            J.Block bl = super.visitBlock(block, executionContext);
            List<J> createFileStatements = getCursor().pollMessage("CREATE_FILE_STATEMENT");
            if (createFileStatements != null) {
                for (J createFileStatement : createFileStatements) {
                    final TempDirHijackingChainStateMachine stateMachine =
                            new TempDirHijackingChainStateMachine();

                    new TempDirHijackingChainFinderVisitor(createFileStatement)
                            .visitNonNull(bl, stateMachine, getCursor().getParentOrThrow());

                    if (stateMachine.isStateMachineSatisfied()) {
                        bl = bl.withStatements(ListUtils.map(bl.getStatements(), stmt -> {
                            if (stmt == stateMachine.getCreateStatement()) {
                                return stateMachine.getSecureCreateStatement();
                            }
                            return stmt;
                        }));
                        maybeAddImport("java.nio.file.Files");
                        Statement delete = stateMachine.getDeleteStatement();
                        bl = deleteOrReplaceStatement(bl, delete, trueLiteral(delete.getPrefix()), executionContext);
                        Statement mkdir = stateMachine.getMkdirStatement();
                        bl = deleteOrReplaceStatement(bl, mkdir, trueLiteral(mkdir.getPrefix()), executionContext);
                        bl = (J.Block) new SimplifyConstantIfBranchExecution()
                                .getVisitor()
                                .visitNonNull(bl, executionContext, getCursor().getParentOrThrow());
                        bl = (J.Block) new SimplifyCompoundVisitor<>()
                                .visitNonNull(bl, executionContext, getCursor().getParentOrThrow());
                    }
                }
            }
            return bl;
        }

        private static J.Literal trueLiteral(Space prefix) {
            return new J.Literal(
                    Tree.randomId(),
                    prefix,
                    Markers.EMPTY,
                    true,
                    "true",
                    null,
                    JavaType.Primitive.Boolean
            );
        }


        private static boolean isMatchingCreateFileStatement(J createFileStatement, Statement statement) {
            if (createFileStatement.equals(statement)) {
                return true;
            } else if (createFileStatement instanceof J.VariableDeclarations.NamedVariable && statement instanceof J.VariableDeclarations) {
                J.VariableDeclarations varDecls = (J.VariableDeclarations) statement;
                return varDecls.getVariables().size() == 1 && varDecls.getVariables().get(0).equals(createFileStatement);
            }
            return false;
        }

        private static boolean isAssignmentForIdent(J.Identifier ident, Statement statement) {
            if (statement instanceof J.Assignment) {
                J.Assignment assignment = (J.Assignment) statement;
                Expression variable = assignment.getVariable();
                if (variable instanceof J.Identifier) {
                    J.Identifier variableIdent = (J.Identifier) variable;
                    return ident.getSimpleName().equals(variableIdent.getSimpleName()) &&
                            TypeUtils.isOfClassType(variableIdent.getType(), "java.io.File");
                }
            }
            return false;
        }

        private static boolean isMethodForIdent(J.Identifier ident, MethodMatcher methodMatcher, Statement statement) {
            if (statement instanceof J.MethodInvocation) {
                J.MethodInvocation mi = (J.MethodInvocation) statement;
                if (mi.getSelect() instanceof J.Identifier && methodMatcher.matches(mi)) {
                    J.Identifier sel = (J.Identifier) mi.getSelect();
                    return ident.getSimpleName().equals(sel.getSimpleName())
                            && TypeUtils.isOfClassType(ident.getType(), "java.io.File");
                }
            }
            return false;
        }

        @Nullable
        private static J.Identifier getIdent(J createFileStatement) {
            if (createFileStatement instanceof J.Assignment) {
                J.Assignment assignment = (J.Assignment) createFileStatement;
                return (J.Identifier) assignment.getVariable();
            } else if (createFileStatement instanceof J.VariableDeclarations.NamedVariable) {
                J.VariableDeclarations.NamedVariable var = (J.VariableDeclarations.NamedVariable) createFileStatement;
                return var.getName();
            }
            return null;
        }
    }

    private static class SecureTempDirectoryCreation<P> extends JavaIsoVisitor<P> {
        private final JavaTemplate twoArg = JavaTemplate.builder(this::getCursor, "Files.createTempDirectory(#{any(String)} + #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        private final JavaTemplate threeArg = JavaTemplate.builder(this::getCursor, "Files.createTempDirectory(#{any(java.io.File)}.toPath(), #{any(String)} + #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, P p) {
            J.MethodInvocation m = method;
            if (CREATE_TEMP_FILE_MATCHER.matches(m)) {
                maybeAddImport("java.nio.file.Files");
                if (m.getArguments().size() == 2) {
                    // File.createTempFile(String prefix, String suffix)
                    m = maybeAutoFormat(m, m.withTemplate(twoArg,
                                    m.getCoordinates().replace(),
                                    m.getArguments().get(0),
                                    m.getArguments().get(1)),
                            p
                    );
                } else if (m.getArguments().size() == 3) {
                    // File.createTempFile(String prefix, String suffix, File dir)
                    m = maybeAutoFormat(m, m.withTemplate(threeArg,
                                    m.getCoordinates().replace(),
                                    m.getArguments().get(2),
                                    m.getArguments().get(0),
                                    m.getArguments().get(1)),
                            p
                    );
                }
            }
            return m;
        }
    }
}
