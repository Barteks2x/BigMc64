package io.github.barteks2x.bigmc64;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.Interpreter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class Main {

    public static void main(String[] args) throws IOException, AnalyzerException {
        Path classFile = Paths.get("build/classes/java/main/io/github/barteks2x/bigmc64/TestExample.class");
        ClassNode cn = new ClassNode(Opcodes.ASM9);
        ClassReader cr = new ClassReader(Files.readAllBytes(classFile));
        cr.accept(cn, 0);

        process(cn);
    }

    private static void process(ClassNode cn) throws AnalyzerException {
        MethodRef test = new MethodRef(Type.getObjectType("io/github/barteks2x/bigmc64/TestExample"), "test", Type.VOID_TYPE,
                new Type[]{Type.INT_TYPE, Type.INT_TYPE, Type.INT_TYPE, Type.INT_TYPE});
        // -1 is return?
        Map<MethodRef, List<Integer>> taggedCoordLocals = new HashMap<>();
        ArrayList<Integer> taggedVars = new ArrayList<>(); // negative = insn
        taggedVars.add(0);
        taggedVars.add(1);
        taggedVars.add(2);
        taggedCoordLocals.put(test, taggedVars);

        for (MethodNode method : cn.methods) {
            if (method.name.equals(test.name) &&
                    Type.getReturnType(method.desc).equals(test.returnType) &&
                    Arrays.equals(Type.getArgumentTypes(method.desc), test.args)) {
                Frame<TaggedValue>[] taggedFrames = inferTaggedValues(cn.name, method, taggedVars);
                MethodNode output = null;//transformToLongs(method, taggedFrames);
            }
        }
    }

    private static Frame<TaggedValue>[] inferTaggedValues(String owner, MethodNode method, ArrayList<Integer> taggedVarsInsns)
            throws AnalyzerException {
        CoordTaggingInterpreter interpreter = new CoordTaggingInterpreter(taggedVarsInsns);
        Analyzer<TaggedValue> analyzer = new Analyzer<>(interpreter);
        Frame<TaggedValue>[] frame = analyzer.analyze(owner, method);
        return frame;
    }

    /**
     * CoordTaggingInterpreter analyzes data flow in a method, and starting from known tagged variables, tries to find
     * other tagged variables, based on the data flow. This is similar to type inference in Java.
     */
    private static class CoordTaggingInterpreter extends Interpreter<TaggedValue> {

        private static final TaggedValue UNINITIALIZED_VALUE = new TaggedValue(null, null, false);

        private final List<Integer> taggedVarsInsns;

        private final List<TaggedValue> locals = new ArrayList<>();

        /**
         * Creates new CoordTaggingInterpreter with initial set of tagged variables
         *
         * @param taggedVarsInsns - initial set of tagged variables
         */
        protected CoordTaggingInterpreter(List<Integer> taggedVarsInsns) {
            super(Opcodes.ASM9);
            this.taggedVarsInsns = taggedVarsInsns;
        }

        @Override public TaggedValue newValue(Type type) {
            throw new UnsupportedOperationException(
                    "This should never be called, we are distinguishing different types, see Interpreter#newValue documentation");
        }

        public TaggedValue newParameterValue(final boolean isInstanceMethod, final int local, final Type type) {
            TaggedValue coordTaggedValue = new TaggedValue(type, local, taggedVarsInsns.contains(local));
            locals.add(coordTaggedValue);
            return coordTaggedValue;
        }

        public TaggedValue newReturnTypeValue(final Type type) {
            if (type == null) {
                return UNINITIALIZED_VALUE;
            }
            if (type == Type.VOID_TYPE) {
                return null;
            }
            return new TaggedValue(type, -1, taggedVarsInsns.contains(-1));
        }

        public TaggedValue newEmptyValue(final int local) {
            return UNINITIALIZED_VALUE;
        }

        public TaggedValue newExceptionValue(
                final TryCatchBlockNode tryCatchBlockNode,
                final Frame<TaggedValue> handlerFrame,
                final Type exceptionType) {
            return new TaggedValue(exceptionType, -1, taggedVarsInsns.contains(-1));
        }

        @Override public TaggedValue newOperation(AbstractInsnNode insn) throws AnalyzerException {
            // all opcodes from superclass javadoc
            return switch (insn.getOpcode()) {
                case Opcodes.ACONST_NULL -> new TaggedValue(Type.getType(Object.class), insn, false);
                case Opcodes.ICONST_M1,
                     Opcodes.ICONST_0,
                     Opcodes.ICONST_1,
                     Opcodes.ICONST_2,
                     Opcodes.ICONST_3,
                     Opcodes.ICONST_4,
                     Opcodes.ICONST_5 -> new TaggedValue(Type.INT_TYPE, insn, false); // fallthrough
                case Opcodes.LCONST_0,
                     Opcodes.LCONST_1 -> new TaggedValue(Type.LONG_TYPE, insn, false);
                case Opcodes.FCONST_0,
                     Opcodes.FCONST_1,
                     Opcodes.FCONST_2 -> new TaggedValue(Type.FLOAT_TYPE, insn, false);
                case Opcodes.DCONST_0,
                     Opcodes.DCONST_1 -> new TaggedValue(Type.DOUBLE_TYPE, insn, false);
                case Opcodes.BIPUSH -> new TaggedValue(Type.BYTE_TYPE, insn, false);
                case Opcodes.SIPUSH -> new TaggedValue(Type.SHORT_TYPE, insn, false);
                case Opcodes.LDC -> new TaggedValue(Type.getType(((LdcInsnNode) insn).cst.getClass()), insn, false);
                case Opcodes.JSR -> throw new AnalyzerException(insn, "JSR is not supported");
                // TODO: support tagging static fields
                case Opcodes.GETSTATIC -> new TaggedValue(Type.getType(((FieldInsnNode) insn).desc), insn, false);
                case Opcodes.NEW -> new TaggedValue(Type.getObjectType(((TypeInsnNode) insn).desc), insn, false);
                default -> throw new AnalyzerException(insn, "Unsupported opcode: " + AsmUtil.opcodeToString(insn.getOpcode()));
            };
        }

        @Override public TaggedValue copyOperation(AbstractInsnNode insn, TaggedValue value) throws AnalyzerException {
            return switch (insn.getOpcode()) {
                case Opcodes.ILOAD -> new TaggedValue(Type.INT_TYPE, insn, value.isCoord());
                case Opcodes.LLOAD -> new TaggedValue(Type.LONG_TYPE, insn, value.isCoord());
                case Opcodes.FLOAD -> new TaggedValue(Type.FLOAT_TYPE, insn, value.isCoord());
                case Opcodes.DLOAD -> new TaggedValue(Type.DOUBLE_TYPE, insn, value.isCoord());
                case Opcodes.ALOAD -> new TaggedValue(value.getType(), insn, value.isCoord());
                case Opcodes.ISTORE -> new TaggedValue(Type.INT_TYPE, insn, value.isCoord());
                case Opcodes.LSTORE -> new TaggedValue(Type.LONG_TYPE, insn, value.isCoord());
                case Opcodes.FSTORE -> new TaggedValue(Type.FLOAT_TYPE, insn, value.isCoord());
                case Opcodes.DSTORE -> new TaggedValue(Type.DOUBLE_TYPE, insn, value.isCoord());
                case Opcodes.ASTORE -> new TaggedValue(value.getType(), insn, value.isCoord());
                case Opcodes.DUP,
                     Opcodes.DUP_X1,
                     Opcodes.DUP_X2,
                     Opcodes.DUP2,
                     Opcodes.DUP2_X1,
                     Opcodes.DUP2_X2,
                     Opcodes.SWAP -> new TaggedValue(value.getType(), insn, value.isCoord());
                default -> throw new AnalyzerException(insn, "Unsupported opcode: " + AsmUtil.opcodeToString(insn.getOpcode()));
            };
        }

        @Override public TaggedValue unaryOperation(AbstractInsnNode insn, TaggedValue value) throws AnalyzerException {
            return switch (insn.getOpcode()) {
                case Opcodes.IFEQ,
                     Opcodes.IFNE,
                     Opcodes.IFLT,
                     Opcodes.IFGE,
                     Opcodes.IFGT,
                     Opcodes.IFLE,
                     Opcodes.TABLESWITCH,
                     Opcodes.LOOKUPSWITCH -> null;
                case Opcodes.IRETURN -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord());
                case Opcodes.LRETURN -> new TaggedValue(Type.LONG_TYPE, insn, false);
                case Opcodes.FRETURN -> new TaggedValue(Type.FLOAT_TYPE, insn, false);
                case Opcodes.DRETURN -> new TaggedValue(Type.DOUBLE_TYPE, insn, false);
                case Opcodes.ARETURN -> new TaggedValue(value.getType(), insn, false);
                case Opcodes.PUTSTATIC -> null;
                case Opcodes.GETFIELD -> new TaggedValue(Type.getType(((FieldInsnNode) insn).desc), insn, value.isCoord());
                case Opcodes.NEWARRAY -> new TaggedValue(AsmUtil.arrayTypeFromOperand(((IntInsnNode) insn).operand), insn, value.isCoord());
                case Opcodes.ANEWARRAY -> new TaggedValue(Type.getObjectType(((TypeInsnNode) insn).desc), insn, value.isCoord());
                case Opcodes.ARRAYLENGTH -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord());
                case Opcodes.ATHROW -> new TaggedValue(value.getType(), insn, false);
                case Opcodes.CHECKCAST -> new TaggedValue(Type.getObjectType(((TypeInsnNode) insn).desc), insn, value.isCoord());
                case Opcodes.INSTANCEOF -> new TaggedValue(Type.BOOLEAN_TYPE, insn, false);
                case Opcodes.MONITORENTER,
                     Opcodes.MONITOREXIT,
                     Opcodes.IFNULL,
                     Opcodes.IFNONNULL -> null;
                case Opcodes.INEG,
                     Opcodes.LNEG,
                     Opcodes.FNEG,
                     Opcodes.DNEG -> new TaggedValue(value.getType(), insn, value.isCoord());
                case Opcodes.IINC -> new TaggedValue(value.getType(), insn, value.isCoord());
                case Opcodes.I2L -> new TaggedValue(Type.LONG_TYPE, insn, false);
                case Opcodes.I2F -> new TaggedValue(Type.FLOAT_TYPE, insn, false);
                case Opcodes.I2D -> new TaggedValue(Type.DOUBLE_TYPE, insn, false);
                case Opcodes.L2I -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord());
                case Opcodes.L2F -> new TaggedValue(Type.FLOAT_TYPE, insn, false);
                case Opcodes.L2D -> new TaggedValue(Type.DOUBLE_TYPE, insn, false);
                case Opcodes.F2I -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord());
                case Opcodes.F2L -> new TaggedValue(Type.LONG_TYPE, insn, false);
                case Opcodes.F2D -> new TaggedValue(Type.DOUBLE_TYPE, insn, false);
                case Opcodes.D2I -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord());
                case Opcodes.D2L -> new TaggedValue(Type.LONG_TYPE, insn, false);
                case Opcodes.D2F -> new TaggedValue(Type.FLOAT_TYPE, insn, false);
                case Opcodes.I2B -> new TaggedValue(Type.BYTE_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord());
                case Opcodes.I2C -> new TaggedValue(Type.CHAR_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord());
                case Opcodes.I2S -> new TaggedValue(Type.SHORT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord());
                default -> throw new AnalyzerException(insn, "Unsupported opcode: " + AsmUtil.opcodeToString(insn.getOpcode()));
            };
        }

        @Override public TaggedValue binaryOperation(AbstractInsnNode insn, TaggedValue value1, TaggedValue value2)
                throws AnalyzerException {
            return switch (insn.getOpcode()) {
                case Opcodes.IALOAD,
                     Opcodes.LALOAD,
                     Opcodes.FALOAD,
                     Opcodes.DALOAD,
                     Opcodes.AALOAD,
                     Opcodes.BALOAD,
                     Opcodes.CALOAD,
                     Opcodes.SALOAD -> new TaggedValue(Type.getObjectType(((TypeInsnNode) insn).desc), insn, value1.isCoord()); // value1 = array
                case Opcodes.IADD,
                     Opcodes.ISUB,
                     Opcodes.IMUL,
                     Opcodes.IDIV,
                     Opcodes.IREM,
                     Opcodes.IAND,
                     Opcodes.IOR,
                     Opcodes.IXOR,
                     Opcodes.ISHL,
                     Opcodes.ISHR,
                     Opcodes.IUSHR -> new TaggedValue(Type.INT_TYPE, insn, value1.isCoord() || value2.isCoord());
                case Opcodes.LADD,
                     Opcodes.LSUB,
                     Opcodes.LMUL,
                     Opcodes.LDIV,
                     Opcodes.LREM,
                     Opcodes.LAND,
                     Opcodes.LOR,
                     Opcodes.LXOR,
                     Opcodes.LSHL,
                     Opcodes.LSHR,
                     Opcodes.LUSHR -> new TaggedValue(Type.LONG_TYPE, insn, false);
                case Opcodes.FADD,
                     Opcodes.FSUB,
                     Opcodes.FMUL,
                     Opcodes.FDIV,
                     Opcodes.FREM -> new TaggedValue(Type.FLOAT_TYPE, insn, false);
                case Opcodes.DADD,
                     Opcodes.DSUB,
                     Opcodes.DMUL,
                     Opcodes.DDIV,
                     Opcodes.DREM -> new TaggedValue(Type.DOUBLE_TYPE, insn, false);
                case Opcodes.LCMP -> new TaggedValue(Type.INT_TYPE, insn, false);
                case Opcodes.FCMPL,
                     Opcodes.FCMPG -> new TaggedValue(Type.FLOAT_TYPE, insn, false);
                case Opcodes.DCMPL,
                     Opcodes.DCMPG -> new TaggedValue(Type.DOUBLE_TYPE, insn, false);
                case Opcodes.IF_ICMPEQ,
                     Opcodes.IF_ICMPNE,
                     Opcodes.IF_ICMPLT,
                     Opcodes.IF_ICMPGE,
                     Opcodes.IF_ICMPGT,
                     Opcodes.IF_ICMPLE,
                     Opcodes.IF_ACMPEQ,
                     Opcodes.IF_ACMPNE -> null;
                // TODO: handle tagging fields
                case Opcodes.PUTFIELD -> null;
                //new TaggedValue(Type.getType(((FieldInsnNode) insn).desc), insn, value1.isCoord() || value2.isCoord());
                default -> throw new AnalyzerException(insn, "Unsupported opcode: " + AsmUtil.opcodeToString(insn.getOpcode()));
            };
        }

        @Override
        public TaggedValue ternaryOperation(AbstractInsnNode insn, TaggedValue arrayValue, TaggedValue indexValue, TaggedValue elementValue)
                throws AnalyzerException {
            return null;
            //return switch (insn.getOpcode()) {
            //    case Opcodes.IASTORE,
            //         Opcodes.LASTORE,
            //         Opcodes.FASTORE,
            //         Opcodes.DASTORE,
            //         Opcodes.AASTORE,
            //         Opcodes.BASTORE,
            //         Opcodes.CASTORE,
            //         Opcodes.SASTORE -> new TaggedValue(
            //            Type.getType(((InsnNode) insn).getClass().getSimpleName().replace("ASTORE", "")),
            //            insn,
            //            arrayValue.isCoord() || indexValue.isCoord() || elementValue.isCoord());
            //    default -> throw new AnalyzerException(insn, "Unsupported opcode: " + AsmUtil.opcodeToString(insn.getOpcode()));
            //};
        }

        @Override public TaggedValue naryOperation(AbstractInsnNode insn, List<? extends TaggedValue> values) throws AnalyzerException {
            // TODO: method calls
            return new TaggedValue(Type.getReturnType(((MethodInsnNode) insn).desc), insn, false);
        }

        @Override public void returnOperation(AbstractInsnNode insn, TaggedValue value, TaggedValue expected) throws AnalyzerException {
            // TODO: do we need to handle returns?
        }

        @Override public TaggedValue merge(TaggedValue value1, TaggedValue value2) {
            if (value1 == UNINITIALIZED_VALUE) {
                return value2;
            }
            if (value2 == UNINITIALIZED_VALUE) {
                return value1;
            }
            if (value1.isCoord() == value2.isCoord()) {
                return value1;
            }
            throw new UnsupportedOperationException("Not implemented");
        }
    }

    private static class TaggedValue extends BasicValue {

        private final Object insnOrLocal;
        private final boolean isCoord;

        public TaggedValue(Type type, AbstractInsnNode insn, boolean isCoord) {
            super(type);
            this.insnOrLocal = insn;
            this.isCoord = isCoord;
        }

        public TaggedValue(Type type, int local, boolean isCoord) {
            super(type);
            this.insnOrLocal = local;
            this.isCoord = isCoord;
        }

        public boolean isInsn() {
            return insnOrLocal instanceof AbstractInsnNode;
        }

        public int getLocal() {
            return (int) insnOrLocal;
        }

        public AbstractInsnNode getInsn() {
            return (AbstractInsnNode) insnOrLocal;
        }

        public boolean isCoord() {
            return isCoord;
        }

        @Override
        public String toString() {
            if (this.getType() == null) {
                return ".";
            }
            String string = super.toString();
            if (!isCoord()) {
                return string.toLowerCase(Locale.ROOT);
            }
            return string;
        }
    }

    private record MethodRef(Type owner, String name, Type returnType, Type[] args) {
    }

    private record InferredType(InferredTypeTag tag, Type type) {
    }

    enum InferredTypeTag {
        NONE, COORD
    }
}
