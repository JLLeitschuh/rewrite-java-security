package org.openrewrite.java.security;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Value;
import org.openrewrite.*;
import org.openrewrite.internal.lang.NonNull;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.controlflow.Guard;
import org.openrewrite.java.dataflow.Dataflow;
import org.openrewrite.java.dataflow.ExternalSinkModels;
import org.openrewrite.java.dataflow.LocalFlowSpec;
import org.openrewrite.java.dataflow.LocalTaintFlowSpec;
import org.openrewrite.java.dataflow.internal.InvocationMatcher;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.security.internal.CursorUtil;
import org.openrewrite.java.security.internal.FileConstructorFixVisitor;
import org.openrewrite.java.security.internal.StringToFileConstructorVisitor;
import org.openrewrite.java.tree.*;
import org.openrewrite.marker.Markers;

import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

@Value
@EqualsAndHashCode(callSuper = true)
public class ZipSlip extends Recipe {
    private static final MethodMatcher ZIP_ENTRY_GET_NAME_METHOD_MATCHER =
            new MethodMatcher("java.util.zip.ZipEntry getName()", true);
    private static final MethodMatcher ZIP_ARCHIVE_ENTRY_GET_NAME_METHOD_MATCHER =
            new MethodMatcher("org.apache.commons.compress.archivers.zip.ZipArchiveEntry getName()", true);

    private static final InvocationMatcher ZIP_ENTRY_GET_NAME = InvocationMatcher.fromInvocationMatchers(
            ZIP_ENTRY_GET_NAME_METHOD_MATCHER,
            ZIP_ARCHIVE_ENTRY_GET_NAME_METHOD_MATCHER
    );

    @Option(displayName = "Debug",
            description = "Debug and output intermediate results.",
            example = "true")
    boolean debug;

    @Override
    public String getDisplayName() {
        return "Zip slip";
    }

    @Override
    public String getDescription() {
        return "Zip slip is an arbitrary file overwrite critical vulnerability, which typically results in remote command execution. " +
                "A fuller description of this vulnerability is available in the [Snyk documentation](https://snyk.io/research/zip-slip-vulnerability) on it.";
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(15);
    }

    @Override
    public boolean causesAnotherCycle() {
        return true;
    }

    @Override
    protected @Nullable TreeVisitor<?, ExecutionContext> getSingleSourceApplicableTest() {
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public JavaSourceFile visitJavaSourceFile(JavaSourceFile cu, ExecutionContext executionContext) {
                doAfterVisit(new UsesMethod<>(ZIP_ENTRY_GET_NAME_METHOD_MATCHER));
                doAfterVisit(new UsesMethod<>(ZIP_ARCHIVE_ENTRY_GET_NAME_METHOD_MATCHER));
                return cu;
            }
        };
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getVisitor() {
        return new ZipSlipComplete<>(true, debug);
    }

    @AllArgsConstructor
    static class ZipSlipComplete<P> extends JavaIsoVisitor<P> {
        boolean fixPartialPathTraversal;
        boolean debug;

        @Override
        public J.Block visitBlock(J.Block block, P p) {
            if (fixPartialPathTraversal) {
                // Fix partial-path first before attempting to fix Zip Slip
                J.Block bPartialPathFix =
                        (J.Block) new PartialPathTraversalVulnerability.PartialPathTraversalVulnerabilityVisitor<>()
                                .visitNonNull(block, p, getCursor().getParentOrThrow());
                if (block != bPartialPathFix) {
                    return bPartialPathFix;
                }
            }
            // Partial-path fix didn't change the block, so we can continue with fixing Zip Slip
            J.Block b = super.visitBlock(block, p);
            if (b != block) {
                // Sometimes this visitor will need to be run multiple times to complete it's work
                // That's okay, just return the new block, we'll run this visitor again later if needed
                return b;
            }
            J.Block superB = b;
            Set<Expression> zipEntryExpressions = computeZipEntryExpressions();
            Supplier<FileConstructorFixVisitor<P>> fileConstructorFixVisitorSupplier =
                    () -> new FileConstructorFixVisitor<>(zipEntryExpressions::contains);
            b = (J.Block) fileConstructorFixVisitorSupplier.get()
                    .visitNonNull(b, p, getCursor().getParentOrThrow());
            b = (J.Block) new StringToFileConstructorVisitor<>(fileConstructorFixVisitorSupplier)
                    .visitNonNull(b, p, getCursor().getParentOrThrow());
            J.Block before = b;
            b = (J.Block) new ZipSlipVisitor<>()
                    .visitNonNull(b, p, getCursor().getParentOrThrow());
            if (before != b || debug) {
                // Only actually make the change if Zip Slip actually fixes a vulnerability
                return b;
            } else {
                return superB;
            }
        }

        /**
         * Compute the set of Expressions that will have been assigned to by a
         * ZipEntry.getName() call.
         */
        private Set<Expression> computeZipEntryExpressions() {
            return CursorUtil.findOuterExecutableBlock(getCursor()).map(outerExecutable -> outerExecutable.computeMessageIfAbsent("computed-zip-entry-expressions", __ -> {
                Set<Expression> zipEntryExpressions = new HashSet<>();
                new JavaIsoVisitor<Set<Expression>>() {
                    @Override
                    public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, Set<Expression> zipEntryExpressionsInternal) {
                        Dataflow.startingAt(getCursor()).findSinks(new ZipEntryToAnyLocalFlowSpec()).ifPresent(sinkFlow ->
                                zipEntryExpressionsInternal.addAll(sinkFlow.getSinks()));
                        return super.visitMethodInvocation(method, zipEntryExpressionsInternal);
                    }
                }.visit(outerExecutable.getValue(), zipEntryExpressions, outerExecutable.getParentOrThrow());
                return zipEntryExpressions;
            })).orElseGet(HashSet::new);
        }
    }

    ;

    private static class ZipEntryToAnyLocalFlowSpec extends LocalFlowSpec<J.MethodInvocation, Expression> {
        @Override
        public boolean isSource(J.MethodInvocation methodInvocation, Cursor cursor) {
            return ZIP_ENTRY_GET_NAME.matches(methodInvocation);
        }

        @Override
        public boolean isSink(Expression expression, Cursor cursor) {
            return true;
        }
    }

    private static class ZipEntryToFileOrPathCreationLocalFlowSpec extends LocalFlowSpec<J.MethodInvocation, Expression> {
        private static final InvocationMatcher FILE_CREATE = InvocationMatcher.fromMethodMatcher(
                new MethodMatcher("java.io.File <constructor>(.., java.lang.String)")
        );
        private static final InvocationMatcher PATH_RESOLVE = InvocationMatcher.fromMethodMatcher(
                new MethodMatcher("java.nio.file.Path resolve(..)")
        );

        @Override
        public boolean isSource(J.MethodInvocation methodInvocation, Cursor cursor) {
            return ZIP_ENTRY_GET_NAME.matches(methodInvocation);
        }

        @Override
        public boolean isSink(Expression expression, Cursor cursor) {
            return FILE_CREATE.advanced().isParameter(cursor, 1) ||
                    PATH_RESOLVE.advanced().isFirstParameter(cursor);
        }
    }

    private static class ZipSlipVisitor<P> extends JavaIsoVisitor<P> {

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, P p) {
            Dataflow.startingAt(getCursor()).findSinks(new ZipEntryToFileOrPathCreationLocalFlowSpec()).ifPresent(sinkFlow ->
                    doAfterVisit(new TaintedFileOrPathVisitor<>(sinkFlow.getSinks()))
            );
            return super.visitMethodInvocation(method, p);
        }

        /**
         * Visitor that handles known tainted {@link java.io.File} or {@link java.nio.file.Path}
         * objects that have been tainted by zip entry getName() calls.
         */
        @AllArgsConstructor
        @EqualsAndHashCode(callSuper = false, onlyExplicitlyIncluded = true)
        private static class TaintedFileOrPathVisitor<P> extends JavaVisitor<P> {
            private static final String IO_EXCEPTION_FQN = "java.io.IOException";
            private static final JavaType IO_EXCEPTION = JavaType.buildType(IO_EXCEPTION_FQN);
            private static final String RUNTIME_EXCEPTION_THROW_LINE = "    throw new RuntimeException(\"Bad zip entry\");\n";
            private static final String IO_EXCEPTION_THROW_LINE = "    throw new IOException(\"Bad zip entry\");\n";

            private JavaTemplate noZipSlipFileTemplate() {
                boolean canSupportIoException = canSupportIoException();
                String exceptionLine = canSupportIoException ? IO_EXCEPTION_THROW_LINE : RUNTIME_EXCEPTION_THROW_LINE;
                JavaTemplate.Builder noZipSlipFileTemplate = JavaTemplate.builder(this::getCursor, "" +
                        "if (!#{any(java.io.File)}.toPath().normalize().startsWith(#{any(java.io.File)}.toPath().normalize())) {\n" +
                        exceptionLine +
                        "}");
                if (canSupportIoException) {
                    noZipSlipFileTemplate.imports(IO_EXCEPTION_FQN);
                }
                return noZipSlipFileTemplate.build();
            }

            private JavaTemplate noZipSlipFileWithStringTemplate() {
                boolean canSupportIoException = canSupportIoException();
                String exceptionLine = canSupportIoException ? IO_EXCEPTION_THROW_LINE : RUNTIME_EXCEPTION_THROW_LINE;
                JavaTemplate.Builder noZipSlipFileWithStringTemplate = JavaTemplate.builder(this::getCursor, "" +
                        "if (!#{any(java.io.File)}.toPath().normalize().startsWith(#{any(String)})) {\n" +
                        exceptionLine +
                        "}");
                if (canSupportIoException) {
                    noZipSlipFileWithStringTemplate.imports(IO_EXCEPTION_FQN);
                }
                return noZipSlipFileWithStringTemplate.build();
            }

            private JavaTemplate noZipSlipPathStartsWithPathTemplate() {
                boolean canSupportIoException = canSupportIoException();
                String exceptionLine = canSupportIoException ? IO_EXCEPTION_THROW_LINE : RUNTIME_EXCEPTION_THROW_LINE;
                JavaTemplate.Builder noZipSlipPathStartsWithPathTemplate = JavaTemplate.builder(this::getCursor, "" +
                        "if (!#{any(java.nio.file.Path)}.normalize().startsWith(#{any(java.nio.file.Path)}.normalize())) {\n" +
                        exceptionLine +
                        "}");
                if (canSupportIoException) {
                    noZipSlipPathStartsWithPathTemplate.imports(IO_EXCEPTION_FQN);
                }
                return noZipSlipPathStartsWithPathTemplate.build();
            }

            private boolean canSupportIoException() {
                Iterator<Cursor> cursors =
                        getCursor()
                                .getPathAsCursors(
                                        c -> isStaticOrInitBlockSafe(c) ||
                                                c.getValue() instanceof J.MethodDeclaration ||
                                                c.getValue() instanceof J.Try
                                );
                while (cursors.hasNext()) {
                    Cursor cursor = cursors.next();
                    if (isStaticOrInitBlockSafe(cursor)) {
                        return false;
                    } else if (cursor.getValue() instanceof J.Try) {
                        J.Try tryBlock = cursor.getValue();
                        if (tryBlock.getCatches().stream().anyMatch(catchClause ->
                                catchClause.getParameter().getTree().getVariables().stream().anyMatch(v ->
                                        TypeUtils.isAssignableTo(v.getType(), IO_EXCEPTION)))) {
                            return true;
                        }
                    } else if (cursor.getValue() instanceof J.MethodDeclaration) {
                        J.MethodDeclaration methodDeclaration = cursor.getValue();
                        if (methodDeclaration.getThrows() != null &&
                                methodDeclaration.getThrows().stream().anyMatch(throwsClause ->
                                        TypeUtils.isAssignableTo(throwsClause.getType(), IO_EXCEPTION))) {
                            return true;
                        }
                    }
                }
                return false;
            }

            private static boolean isStaticOrInitBlockSafe(Cursor cursor) {
                return cursor.getValue() instanceof J.Block && J.Block.isStaticOrInitBlock(cursor);
            }

            @EqualsAndHashCode.Include
            private final List<Expression> taintedSinks;

            @Value
            @NonNull
            private static class ZipSlipSimpleInjectGuardInfo {
                static String CURSOR_KEY = "ZipSlipSimpleInjectGuardInfo";
                /**
                 * The statement to create the guard after.
                 */
                Statement statement;
                /**
                 * The parent directory expression to create the guard for.
                 */
                Expression parentDir;
                /**
                 * The child file created with the zip entry to create the guard for.
                 */
                Expression zipEntry;
            }

            @Value
            @NonNull
            public static class ZipSlipCreateNewVariableInfo {
                static String CURSOR_KEY = "ZipSlipCreateNewVariableInfo";
                String newVariableName;
                /**
                 * The statement to extract the new variable to before.
                 */
                Statement statement;
                /**
                 * The expression that needs to be extracted to a new variable.
                 */
                MethodCall extractToVariable;
            }

            @Override
            public J visitAssignment(J.Assignment assignment, P p) {
                J newAssignment = super.visitAssignment(assignment, p);
                if (assignment != newAssignment) {
                    return maybeAutoFormat(assignment, newAssignment, p, getCursor().getParentOrThrow());
                }
                return newAssignment;
            }

            @Override
            public J visitMethodInvocation(J.MethodInvocation method, P p) {
                return visitMethodCall(method, J.MethodInvocation::getSelect)
                        .<J>map(Function.identity())
                        .orElseGet(() -> super.visitMethodInvocation(method, p));
            }

            @Override
            public J visitNewClass(J.NewClass newClass, P p) {
                return visitMethodCall(newClass, n -> n.getArguments().get(0))
                        .<J>map(Function.identity())
                        .orElseGet(() -> super.visitNewClass(newClass, p));
            }

            private <M extends MethodCall> Optional<J.Identifier> visitMethodCall(M methodCall, Function<M, Expression> parentDirExtractor) {
                if (methodCall.getArguments().stream().anyMatch(taintedSinks::contains)
                        && Dataflow.startingAt(getCursor()).findSinks(new FileOrPathCreationToVulnerableUsageLocalFlowSpec()).isPresent()) {
                    J.Block firstEnclosingBlock = getCursor().firstEnclosingOrThrow(J.Block.class);
                    @SuppressWarnings("SuspiciousMethodCalls")
                    Statement enclosingStatement = getCursor()
                            .dropParentUntil(value -> firstEnclosingBlock.getStatements().contains(value))
                            .getValue();

                    J.VariableDeclarations.NamedVariable enclosingVariable =
                            getCursor().firstEnclosing(J.VariableDeclarations.NamedVariable.class);

                    if (enclosingVariable != null && Expression.unwrap(enclosingVariable.getInitializer()) == methodCall) {
                        J.VariableDeclarations variableDeclarations = getCursor().firstEnclosing(J.VariableDeclarations.class);
                        J.Identifier enclosingVariableIdentifier;
                        if (variableDeclarations != null && variableDeclarations.getVariables().contains(enclosingVariable)) {
                            // Bug fix for https://github.com/openrewrite/rewrite/issues/2118
                            enclosingVariableIdentifier = enclosingVariable.getName().withType(variableDeclarations.getType());
                        } else {
                            enclosingVariableIdentifier = enclosingVariable.getName();
                        }

                        final ZipSlipSimpleInjectGuardInfo zipSlipSimpleInjectGuardInfo =
                                new ZipSlipSimpleInjectGuardInfo(
                                        enclosingStatement,
                                        parentDirExtractor.apply(methodCall),
                                        enclosingVariableIdentifier
                                );
                        getCursor()
                                .dropParentUntil(J.Block.class::isInstance)
                                .putMessage(
                                        ZipSlipSimpleInjectGuardInfo.CURSOR_KEY,
                                        zipSlipSimpleInjectGuardInfo
                                );
                    } else {
                        String newVariableBaseName;
                        if (isTypePath(methodCall.getType())) {
                            newVariableBaseName = "zipEntryPath";
                        } else {
                            assert isTypeFile(methodCall.getType()) :
                                    "Expected method call to be of type `java.io.File` or `java.nio.file.Path` but was `" + methodCall.getType() + "`";
                            newVariableBaseName = "zipEntryFile";
                        }
                        String newVariableName = VariableNameUtils.generateVariableName(
                                newVariableBaseName,
                                getCursor(),
                                VariableNameUtils.GenerationStrategy.INCREMENT_NUMBER
                        );
                        final ZipSlipCreateNewVariableInfo zipSlipCreateNewVariableInfo =
                                new ZipSlipCreateNewVariableInfo(
                                        newVariableName,
                                        enclosingStatement,
                                        methodCall
                                );
                        getCursor()
                                .dropParentUntil(J.Block.class::isInstance)
                                .putMessage(
                                        ZipSlipCreateNewVariableInfo.CURSOR_KEY,
                                        zipSlipCreateNewVariableInfo
                                );
                        return Optional.of(new J.Identifier(
                                Tree.randomId(),
                                Space.EMPTY,
                                Markers.EMPTY,
                                newVariableName,
                                methodCall.getType(),
                                null
                        ));
                    }
                }
                return Optional.empty();
            }

            @Override
            public J.Block visitBlock(J.Block block, P p) {
                J.Block b = (J.Block) super.visitBlock(block, p);
                ZipSlipCreateNewVariableInfo zipSlipCreateNewVariableInfo = getCursor().pollMessage(ZipSlipCreateNewVariableInfo.CURSOR_KEY);
                if (zipSlipCreateNewVariableInfo != null) {
                    JavaTemplate newVariableTemplate;
                    if (isTypePath(zipSlipCreateNewVariableInfo.extractToVariable.getType())) {
                        newVariableTemplate = JavaTemplate
                                .builder(
                                        this::getCursor,
                                        "final Path " + zipSlipCreateNewVariableInfo.newVariableName + " = #{any(java.nio.file.Path)};"
                                )
                                .imports("java.nio.file.Path")
                                .build();
                        maybeAddImport("java.nio.file.Path");
                    } else {
                        assert isTypeFile(zipSlipCreateNewVariableInfo.extractToVariable.getType());
                        newVariableTemplate = JavaTemplate
                                .builder(
                                        this::getCursor,
                                        "final File " + zipSlipCreateNewVariableInfo.newVariableName + " = #{any(java.io.File)};"
                                )
                                .imports("java.io.File")
                                .build();
                        maybeAddImport("java.io.File");
                    }
                    return b.withTemplate(
                            newVariableTemplate,
                            zipSlipCreateNewVariableInfo.statement.getCoordinates().before(),
                            zipSlipCreateNewVariableInfo.extractToVariable
                    );
                }
                ZipSlipSimpleInjectGuardInfo zipSlipSimpleInjectGuardInfo = getCursor().pollMessage(ZipSlipSimpleInjectGuardInfo.CURSOR_KEY);
                if (zipSlipSimpleInjectGuardInfo != null) {
                    JavaTemplate template;
                    if (isTypeFile(zipSlipSimpleInjectGuardInfo.zipEntry.getType())) {
                        if (isTypeFile(zipSlipSimpleInjectGuardInfo.parentDir.getType())) {
                            template = noZipSlipFileTemplate();
                        } else {
                            assert TypeUtils.isString(zipSlipSimpleInjectGuardInfo.parentDir.getType());
                            template = noZipSlipFileWithStringTemplate();
                        }
                    } else {
                        assert isTypePath(zipSlipSimpleInjectGuardInfo.zipEntry.getType());
                        template = noZipSlipPathStartsWithPathTemplate();
                    }
                    return b.withTemplate(
                            template,
                            zipSlipSimpleInjectGuardInfo.statement.getCoordinates().after(),
                            zipSlipSimpleInjectGuardInfo.zipEntry,
                            zipSlipSimpleInjectGuardInfo.parentDir
                    );
                }
                return b;
            }
        }

        private static class FileOrPathCreationToVulnerableUsageLocalFlowSpec extends LocalTaintFlowSpec<Expression, Expression> {
            private static final MethodMatcher PATH_STARTS_WITH_MATCHER =
                    new MethodMatcher("java.nio.file.Path startsWith(..) ");
            private static final MethodMatcher STRING_STARTS_WITH_MATCHER =
                    new MethodMatcher("java.lang.String startsWith(..) ");

            @Override
            public boolean isSource(Expression expression, Cursor cursor) {
                return true;
            }

            @Override
            public boolean isSink(Expression expression, Cursor cursor) {
                return ExternalSinkModels.getInstance().isSinkNode(expression, cursor, "create-file");
            }

            @Override
            public boolean isSanitizerGuard(Guard guard, boolean branch) {
                if (branch) {
                    return PATH_STARTS_WITH_MATCHER.matches(guard.getExpression()) ||
                            (STRING_STARTS_WITH_MATCHER.matches(guard.getExpression()) &&
                                    PartialPathTraversalVulnerability.isSafePartialPathExpression(((J.MethodInvocation) guard.getExpression()).getArguments().get(0)));
                } else {
                    return false;
                }
            }
        }
    }

    private static boolean isTypeFile(@Nullable JavaType type) {
        return TypeUtils.isOfClassType(type, "java.io.File");
    }

    private static boolean isTypePath(@Nullable JavaType type) {
        return TypeUtils.isOfClassType(type, "java.nio.file.Path");
    }
}
