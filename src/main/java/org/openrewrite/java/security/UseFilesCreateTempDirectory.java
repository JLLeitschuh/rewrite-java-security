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
import org.openrewrite.Recipe;
import org.openrewrite.Tree;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.cleanup.SimplifyConstantIfBranchExecution;
import org.openrewrite.java.marker.JavaVersion;
import org.openrewrite.java.search.FindReferencedTypes;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.*;
import org.openrewrite.marker.Markers;

import java.time.Duration;
import java.util.*;

import static java.util.Collections.emptyList;
import static org.openrewrite.Tree.randomId;

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
    protected UsesFilesCreateTempDirVisitor getVisitor() {
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

        @AllArgsConstructor
        private static class TempDirHijackingChainFinderVisitor extends JavaIsoVisitor<Map<String, Statement>> {
            private J createFileStatement;

            @Override
            public Statement visitStatement(Statement stmt, Map<String, Statement> stmtMap) {
                Statement s = super.visitStatement(stmt, stmtMap);
                J.Identifier createFileIdentifier = getIdent(createFileStatement);
                if (createFileIdentifier != null) {
                    if (isMatchingCreateFileStatement(createFileStatement, stmt)) {
                        stmtMap.put("create", stmt);
                        stmtMap.put("secureCreate", (Statement) new SecureTempDirectoryCreation<>().visitNonNull(stmt, stmtMap, getCursor().getParentOrThrow()));
                    } else if (isMethodForIdent(createFileIdentifier, DELETE_MATCHER, stmt)) {
                        stmtMap.put("delete", stmt);
                    } else if (isMethodForIdent(createFileIdentifier, MKDIR_MATCHER, stmt)
                            || isMethodForIdent(createFileIdentifier, MKDIRS_MATCHER, stmt)) {
                        stmtMap.put("mkdir", stmt);
                    }
                }
                return s;
            }
        }

        private static class DeleteOrElseReplaceStatement<P> extends DeleteStatementNonIso<P> {
            private final Statement statement;
            private final Expression replacement;

            public DeleteOrElseReplaceStatement(Statement statement, Expression replacement) {
                super(statement);
                this.statement = statement;
                this.replacement = replacement;
            }

            @Override
            public Expression visitExpression(Expression expression, P p) {
                // The statement should only be replaced when removing would cause invalid code.
                if (expression == statement &&
                        // If the direct parent of this expression is a `J.Block` then it should be removed by `DeleteStatementNonIso`.
                        !(getCursor().getParentOrThrow(2).getValue() instanceof J.Block)) {
                    return replacement;
                }
                return (Expression) super.visitExpression(expression, p);
            }
        }

        @Override
        public J.Block visitBlock(J.Block block, ExecutionContext executionContext) {
            J.Block bl = super.visitBlock(block, executionContext);
            List<J> createFileStatements = getCursor().pollMessage("CREATE_FILE_STATEMENT");
            if (createFileStatements != null) {
                for (J createFileStatement : createFileStatements) {
                    final Map<String, Statement> stmtMap = new HashMap<>();

                    new TempDirHijackingChainFinderVisitor(createFileStatement)
                            .visitNonNull(bl, stmtMap, getCursor().getParentOrThrow());

                    if (stmtMap.size() == 4) {
                        bl = bl.withStatements(ListUtils.map(bl.getStatements(), stmt -> {
                            if (stmt == stmtMap.get("create")) {
                                return stmtMap.get("secureCreate");
                            }
                            return stmt;
                        }));
                        maybeAddImport("java.nio.file.Files");
                        Statement delete = stmtMap.get("delete");
                        bl = (J.Block) new DeleteOrElseReplaceStatement<>(
                                delete,
                                trueLiteral(delete.getPrefix())
                        ).visitNonNull(bl, executionContext, getCursor().getParentOrThrow());
                        Statement mkdir = stmtMap.get("mkdir");
                        bl = (J.Block) new DeleteOrElseReplaceStatement<>(
                                mkdir,
                                trueLiteral(mkdir.getPrefix())
                        ).visitNonNull(bl, executionContext, getCursor().getParentOrThrow());
                        // TODO: Only visit this particular block, not the entire file.
                        doAfterVisit(new SimplifyConstantIfBranchExecution());
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

/**
 * Deletes standalone statements. Does not include deletion of control statements present in for loops.
 */
class DeleteStatementNonIso<P> extends JavaVisitor<P> {
    private final Statement statement;

    public DeleteStatementNonIso(Statement statement) {
        this.statement = statement;
    }

    @Override
    public J.If visitIf(J.If iff, P p) {
        J.If i = (J.If) super.visitIf(iff, p);
        if (statement.isScope(i.getThenPart())) {
            i = i.withThenPart(emptyBlock());
        } else if (i.getElsePart() != null && statement.isScope(i.getElsePart())) {
            i = i.withElsePart(i.getElsePart().withBody(emptyBlock()));
        }

        return i;
    }

    @Override
    public J.ForLoop visitForLoop(J.ForLoop forLoop, P p) {
        return statement.isScope(forLoop.getBody()) ?
                forLoop.withBody(emptyBlock()) :
                (J.ForLoop) super.visitForLoop(forLoop, p);
    }

    @Override
    public J.ForEachLoop visitForEachLoop(J.ForEachLoop forEachLoop, P p) {
        return statement.isScope(forEachLoop.getBody()) ?
                forEachLoop.withBody(emptyBlock()) :
                (J.ForEachLoop) super.visitForEachLoop(forEachLoop, p);
    }

    @Override
    public J.WhileLoop visitWhileLoop(J.WhileLoop whileLoop, P p) {
        return statement.isScope(whileLoop.getBody()) ? whileLoop.withBody(emptyBlock()) :
                (J.WhileLoop) super.visitWhileLoop(whileLoop, p);
    }

    @Override
    public J.DoWhileLoop visitDoWhileLoop(J.DoWhileLoop doWhileLoop, P p) {
        return statement.isScope(doWhileLoop.getBody()) ? doWhileLoop.withBody(emptyBlock()) :
                (J.DoWhileLoop) super.visitDoWhileLoop(doWhileLoop, p);
    }

    @Override
    public J.Block visitBlock(J.Block block, P p) {
        J.Block b = (J.Block) super.visitBlock(block, p);
        return b.withStatements(ListUtils.map(b.getStatements(), s ->
                statement.isScope(s) ? null : s));
    }

    @Override
    public J preVisit(J tree, P p) {
        if (statement.isScope(tree)) {
            for (JavaType.FullyQualified referenced : FindReferencedTypes.find(tree)) {
                maybeRemoveImport(referenced);
            }
        }
        return super.preVisit(tree, p);
    }

    private Statement emptyBlock() {
        return new J.Block(randomId(),
                Space.EMPTY,
                Markers.EMPTY,
                null,
                emptyList(),
                Space.EMPTY
        );
    }
}
