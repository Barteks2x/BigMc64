package io.github.barteks2x.bigmc64;

import static io.github.barteks2x.bigmc64.Main.InferredTypeTag.COORD;
import static io.github.barteks2x.bigmc64.Main.InferredTypeTag.NONE;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.Interpreter;
import org.objectweb.asm.tree.analysis.SimpleVerifier;

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
import java.util.Objects;

public class Main {

    public static void main(String[] args) throws IOException, AnalyzerException {
        JarTagIndex index = new JarTagIndex();
        Type testExampleType = Type.getType("Lio/github/barteks2x/bigmc64/TestExample;");
        MethodRef testMethodRef = new MethodRef(testExampleType, false, "test", Type.VOID_TYPE,
                Type.INT_TYPE, Type.INT_TYPE, Type.INT_TYPE, Type.INT_TYPE);
        TaggedClassInfo testExampleTags = new TaggedClassInfo(testExampleType);
        testExampleTags.addMethod(testMethodRef, new MethodTags(NONE, COORD, COORD, COORD, NONE));
        index.addClass(testExampleType, testExampleTags);

        Path classFile = Paths.get("build/classes/java/main/io/github/barteks2x/bigmc64/TestExample.class");
        ClassNode cn = new ClassNode(Opcodes.ASM9);
        ClassReader cr = new ClassReader(Files.readAllBytes(classFile));
        cr.accept(cn, 0);

        process(index, cn);

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);// | ClassWriter.COMPUTE_FRAMES);
        cn.accept(cw);
        byte[] byteArray = cw.toByteArray();
        Files.write(Paths.get("TestExample.class"), byteArray);

        cr = new ClassReader(byteArray);
        cn = new ClassNode();
        cr.accept(cn, 0);

        SimpleVerifier verifier = new SimpleVerifier(Type.getObjectType(cn.name),
                Type.getObjectType("java/lang/Object"), false);
        Analyzer<?> analyzer = new Analyzer<>(verifier);
        for (MethodNode method : cn.methods) {
            System.out.println("Method " + method.name);
            analyzer.analyze(cn.name, method);
        }
    }

    private static void process(JarTagIndex index, ClassNode cn) throws AnalyzerException {
        List<MethodNode> methods = cn.methods;
        for (int i = 0; i < methods.size(); i++) {
            MethodNode method = methods.get(i);
            Frame<TaggedValue>[] taggedFrames = inferTaggedValues(cn.name, method, index);
            MethodNode output = transformToLongs(index, method, taggedFrames);
            cn.methods.set(i, output);
        }
    }

    private static MethodNode transformToLongs(JarTagIndex index, MethodNode method, Frame<TaggedValue>[] taggedFrames) {
        MethodNode newNode = new MethodNode(Opcodes.ASM9, method.name, transformDescriptor(taggedFrames, method.desc), null,
                method.exceptions.toArray(String[]::new));
        newNode.access = method.access;
        newNode.visibleLocalVariableAnnotations = method.visibleLocalVariableAnnotations;
        newNode.invisibleLocalVariableAnnotations = method.invisibleLocalVariableAnnotations;
        // TODO: tryCatchBlocks

        newNode.instructions = new InsnList();
        newNode.maxStack = method.maxStack;

        newNode.localVariables = new ArrayList<>();
        for (LocalVariableNode localVariable : method.localVariables) {
            String newDesc = localVariable.desc;
            Frame<TaggedValue> frame0 = taggedFrames[method.instructions.indexOf(localVariable.start)];
            if (frame0.getLocal(localVariable.index).isCoord()) {
                newDesc = "J";
            }
            LocalVariableNode newLocal = new LocalVariableNode(localVariable.name, newDesc, null, localVariable.start, localVariable.end,
                    recomputeLocalIndex(localVariable.index, frame0));
            newNode.localVariables.add(newLocal);
        }
        transformInsns(index, method.instructions, newNode.instructions, taggedFrames);
        return newNode;
    }

    private static String transformDescriptor(Frame<TaggedValue>[] taggedFrames, String desc) {
        Type returnType = Type.getReturnType(desc);
        Type[] args = Type.getArgumentTypes(desc);
        StringBuilder sb = new StringBuilder("(");
        Frame<TaggedValue> firstFrame = taggedFrames[0];

        for (int i = 0, local = 0; i < args.length; i++) {
            Type arg = args[i];
            if (firstFrame.getLocal(local).isCoord()) {
                if (arg == Type.INT_TYPE) {
                    sb.append("J");
                } else {
                    throw new UnsupportedOperationException("Only ints can be coords");
                }
            } else {
                sb.append(arg.getDescriptor());
            }
            local += arg.getSize();
        }
        sb.append(')');
        sb.append(returnType);
        return sb.toString();
    }

    private static void transformInsns(JarTagIndex index, InsnList oldInsns, InsnList newInsns, Frame<TaggedValue>[] frames) {
        AbstractInsnNode insn = oldInsns.getFirst();
        for (int i = 0; i < oldInsns.size(); i++, insn = insn.getNext()) {
            Frame<TaggedValue> frame = frames[i];
            int opcode = insn.getOpcode();
            switch (opcode) {
                case -1 -> {
                    newInsns.add(insn);
                }
                case Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2, Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
                     Opcodes.LCONST_0, Opcodes.LCONST_1,
                     Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2,
                     Opcodes.DCONST_0, Opcodes.DCONST_1,
                     Opcodes.BIPUSH -> newInsns.add(insn);
                case Opcodes.ISTORE, Opcodes.ILOAD -> {
                    int oldLocal = ((VarInsnNode) insn).var;
                    int newLocal = recomputeLocalIndex(oldLocal, frame);
                    if (frame.getLocal(oldLocal).isCoord()) {
                        newInsns.add(new VarInsnNode(AsmUtil.intToLongOpcode(opcode), newLocal));
                    } else {
                        newInsns.add(new VarInsnNode(opcode, newLocal));
                    }
                }
                case Opcodes.ASTORE, Opcodes.ALOAD -> {
                    int oldLocal = ((VarInsnNode) insn).var;
                    int newLocal = recomputeLocalIndex(oldLocal, frame);
                    newInsns.add(new VarInsnNode(opcode, newLocal));
                }
                case Opcodes.IF_ICMPGT, Opcodes.IF_ICMPGE -> {
                    if (frame.getStack(frame.getStackSize() - 1).isCoord()) {
                        newInsns.add(new InsnNode(Opcodes.LCMP));
                    }
                    newInsns.add(insn);
                }
                case Opcodes.IADD, Opcodes.IMUL -> {
                    if (frame.getStack(frame.getStackSize() - 2).isCoord() && !frame.getStack(frame.getStackSize() - 1).isCoord()) {
                        newInsns.add(new InsnNode(Opcodes.I2L));
                        newInsns.add(new InsnNode(AsmUtil.intToLongOpcode(opcode)));
                    } else if (!frame.getStack(frame.getStackSize() - 2).isCoord() && frame.getStack(frame.getStackSize() - 1).isCoord()) {
                        // find new local index for a long
                        int newLocal = recomputeLocalIndex(frame.getLocals(), frame);
                        newInsns.add(new VarInsnNode(Opcodes.LSTORE, newLocal));
                        newInsns.add(new InsnNode(Opcodes.I2L));
                        newInsns.add(new VarInsnNode(Opcodes.LLOAD, newLocal));
                        newInsns.add(new InsnNode(AsmUtil.intToLongOpcode(opcode)));
                    } else if (frame.getStack(frame.getStackSize() - 2).isCoord() && frame.getStack(frame.getStackSize() - 1).isCoord()) {
                        newInsns.add(new InsnNode(AsmUtil.intToLongOpcode(opcode)));
                    } else {
                        newInsns.add(insn);
                    }
                }
                case Opcodes.IINC -> {
                    int local = ((IincInsnNode) insn).var;
                    int newLocal = recomputeLocalIndex(local, frame);
                    int incr = ((IincInsnNode) insn).incr;
                    if (frame.getLocal(local).isCoord()) {
                        // increment a long
                        newInsns.add(new VarInsnNode(Opcodes.LLOAD, newLocal)); // load the long
                        newInsns.add(new IntInsnNode(Opcodes.BIPUSH, incr)); // push incr as byte
                        newInsns.add(new InsnNode(Opcodes.I2L)); // convert it to long
                        newInsns.add(new InsnNode(Opcodes.LADD)); // add them together
                        newInsns.add(new VarInsnNode(Opcodes.LSTORE, newLocal)); // store back into memory
                    } else {
                        // increment an integer
                        newInsns.add(new IincInsnNode(newLocal, incr));
                    }
                }
                case Opcodes.DUP -> {
                    if (frame.getStack(frame.getStackSize() - 1).isCoord()) {
                        // dup a long
                        newInsns.add(new InsnNode(Opcodes.DUP2));
                    } else {
                        // dup an integer
                        newInsns.add(insn);
                    }
                }
                case Opcodes.POP -> {
                    if (frame.getStack(frame.getStackSize() - 1).isCoord()) {
                        // pop a long
                        newInsns.add(new InsnNode(Opcodes.POP2));
                    } else {
                        // pop an integer
                        newInsns.add(insn);
                    }
                }
                case Opcodes.GETSTATIC -> {
                    System.out.println("TODO: GETSTATIC");
                    newInsns.add(insn);
                }
                case Opcodes.INVOKESTATIC -> {
                    MethodInsnNode call = (MethodInsnNode) insn;
                    if (call.owner.equals("java/lang/Integer") && call.name.equals("valueOf")
                            && call.desc.equals("(I)Ljava/lang/Integer;") && frame.getStack(frame.getStackSize() - 1).isCoord()) {
                        newInsns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;"));
                    } else {
                        Type returnType = Type.getReturnType(call.desc);
                        Type[] argumentTypes = Type.getArgumentTypes(call.desc);
                        MethodRef ref = new MethodRef(Type.getObjectType(call.owner), false, call.name,
                                returnType, argumentTypes);
                        MethodTags tags = index.getClassTags(ref.owner()).getMethod(ref);
                        if (tags.inferredReturn == COORD) {
                            assert returnType == Type.INT_TYPE;
                            returnType = Type.LONG_TYPE;
                        }
                        for (int j = 0; j < tags.inferredArgs.length; j++) {
                            if (tags.inferredArgs[j] == COORD) {
                                assert argumentTypes[j] == Type.INT_TYPE;
                                argumentTypes[j] = Type.LONG_TYPE;
                            }
                        }
                        newInsns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, call.owner, call.name,
                                Type.getMethodDescriptor(returnType, argumentTypes)));
                    }
                }
                case Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESPECIAL -> {
                    System.out.println("TODO: " + AsmUtil.opcodeToString(opcode));
                    newInsns.add(insn);
                }
                case Opcodes.LDC -> {
                    System.out.println("TODO: LDC");
                    newInsns.add(insn);
                }
                case Opcodes.ANEWARRAY -> {
                    System.out.println("TODO: ANEWARRAY");
                    newInsns.add(insn);
                }
                case Opcodes.AASTORE -> {
                    System.out.println("TODO: AASTORE");
                    newInsns.add(insn);
                }
                case Opcodes.GOTO -> {
                    System.out.println("TODO: GOTO");
                    newInsns.add(insn);
                }
                case Opcodes.RETURN -> {
                    System.out.println("TODO: RETURN");
                    newInsns.add(insn);
                }
                default -> throw new UnsupportedOperationException("Unimplemented opcode: " + AsmUtil.opcodeToString(opcode));
            }
        }
    }

    private static int recomputeLocalIndex(int oldLocal, Frame<TaggedValue> frame) {
        int i = 0, j = 0;
        while (i < oldLocal) {
            TaggedValue local = frame.getLocal(i);
            i += local.getSize();
            j += local.isCoord ? 2 : local.getSize();
        }
        assert i == oldLocal;
        return j;
    }

    private static Frame<TaggedValue>[] inferTaggedValues(String ownerInternalName, MethodNode method, JarTagIndex index)
            throws AnalyzerException {
        CoordTaggingInterpreter interpreter = new CoordTaggingInterpreter(index, new MethodRef(Type.getObjectType(ownerInternalName),
                (method.access & Opcodes.ACC_STATIC) == 0,
                method.name, Type.getReturnType(method.desc), Type.getArgumentTypes(method.desc)));
        Analyzer<TaggedValue> analyzer = new Analyzer<>(interpreter);
        Frame<TaggedValue>[] frame = analyzer.analyze(ownerInternalName, method);
        return frame;
    }

    /**
     * CoordTaggingInterpreter analyzes data flow in a method, and starting from known tagged variables, tries to find
     * other tagged variables, based on the data flow. This is similar to type inference in Java.
     */
    private static class CoordTaggingInterpreter extends Interpreter<TaggedValue> {

        private static final TaggedValue UNINITIALIZED_VALUE = new TaggedValue(null, null, false);

        private final JarTagIndex index;
        private final MethodRef thisMethodRef;

        private final List<TaggedValue> locals = new ArrayList<>();
        private final MethodTags thisMethodTags;

        /**
         * Creates new CoordTaggingInterpreter with initial set of tagged variables
         *
         * @param index - initial set of tagged variables
         */
        protected CoordTaggingInterpreter(JarTagIndex index, MethodRef thisMethod) {
            super(Opcodes.ASM9);
            System.out.println("Making interpreter for " + thisMethod);
            this.index = index;
            this.thisMethodRef = thisMethod;
            this.thisMethodTags = index.getClassTags(thisMethod.owner()).getMethod(thisMethodRef);
        }

        @Override public TaggedValue newValue(Type type) {
            throw new UnsupportedOperationException(
                    "This should never be called, we are distinguishing different types, see Interpreter#newValue documentation");
        }

        public TaggedValue newParameterValue(final boolean isInstanceMethod, final int local, final Type type) {
            TaggedValue coordTaggedValue = new TaggedValue(type, local, thisMethodTags.inferredArgs[local] == COORD);
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
            return new TaggedValue(type, -1, thisMethodTags.inferredReturn == COORD);
        }

        public TaggedValue newEmptyValue(final int local) {
            return UNINITIALIZED_VALUE;
        }

        public TaggedValue newExceptionValue(
                final TryCatchBlockNode tryCatchBlockNode,
                final Frame<TaggedValue> handlerFrame,
                final Type exceptionType) {
            return new TaggedValue(exceptionType, -1, false);
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
                case Opcodes.ILOAD -> new TaggedValue(Type.INT_TYPE, insn, value.isCoord(), value);
                case Opcodes.LLOAD -> new TaggedValue(Type.LONG_TYPE, insn, value.isCoord(), value);
                case Opcodes.FLOAD -> new TaggedValue(Type.FLOAT_TYPE, insn, value.isCoord(), value);
                case Opcodes.DLOAD -> new TaggedValue(Type.DOUBLE_TYPE, insn, value.isCoord(), value);
                case Opcodes.ALOAD -> new TaggedValue(value.getType(), insn, value.isCoord(), value);
                case Opcodes.ISTORE -> new TaggedValue(Type.INT_TYPE, insn, value.isCoord(), value);
                case Opcodes.LSTORE -> new TaggedValue(Type.LONG_TYPE, insn, value.isCoord(), value);
                case Opcodes.FSTORE -> new TaggedValue(Type.FLOAT_TYPE, insn, value.isCoord(), value);
                case Opcodes.DSTORE -> new TaggedValue(Type.DOUBLE_TYPE, insn, value.isCoord(), value);
                case Opcodes.ASTORE -> new TaggedValue(value.getType(), insn, value.isCoord(), value);
                case Opcodes.DUP,
                     Opcodes.DUP_X1,
                     Opcodes.DUP_X2,
                     Opcodes.DUP2,
                     Opcodes.DUP2_X1,
                     Opcodes.DUP2_X2,
                     Opcodes.SWAP -> new TaggedValue(value.getType(), insn, value.isCoord(), value);
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
                case Opcodes.IRETURN -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord(), value);
                case Opcodes.LRETURN -> new TaggedValue(Type.LONG_TYPE, insn, false, value);
                case Opcodes.FRETURN -> new TaggedValue(Type.FLOAT_TYPE, insn, false, value);
                case Opcodes.DRETURN -> new TaggedValue(Type.DOUBLE_TYPE, insn, false, value);
                case Opcodes.ARETURN -> new TaggedValue(value.getType(), insn, false, value);
                case Opcodes.PUTSTATIC -> null;
                case Opcodes.GETFIELD -> new TaggedValue(Type.getType(((FieldInsnNode) insn).desc), insn, value.isCoord(), value);
                case Opcodes.NEWARRAY -> new TaggedValue(AsmUtil.arrayTypeFromOperand(((IntInsnNode) insn).operand), insn, value.isCoord(), value);
                case Opcodes.ANEWARRAY -> new TaggedValue(Type.getObjectType(((TypeInsnNode) insn).desc), insn, value.isCoord(), value);
                case Opcodes.ARRAYLENGTH -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord(), value);
                case Opcodes.ATHROW -> new TaggedValue(value.getType(), insn, false, value);
                case Opcodes.CHECKCAST -> new TaggedValue(Type.getObjectType(((TypeInsnNode) insn).desc), insn, value.isCoord(), value);
                case Opcodes.INSTANCEOF -> new TaggedValue(Type.BOOLEAN_TYPE, insn, false, value);
                case Opcodes.MONITORENTER,
                     Opcodes.MONITOREXIT,
                     Opcodes.IFNULL,
                     Opcodes.IFNONNULL -> null;
                case Opcodes.INEG,
                     Opcodes.LNEG,
                     Opcodes.FNEG,
                     Opcodes.DNEG -> new TaggedValue(value.getType(), insn, value.isCoord(), value);
                case Opcodes.IINC -> new TaggedValue(value.getType(), insn, value.isCoord(), value);
                case Opcodes.I2L -> new TaggedValue(Type.LONG_TYPE, insn, false, value);
                case Opcodes.I2F -> new TaggedValue(Type.FLOAT_TYPE, insn, false, value);
                case Opcodes.I2D -> new TaggedValue(Type.DOUBLE_TYPE, insn, false, value);
                case Opcodes.L2I -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord(), value);
                case Opcodes.L2F -> new TaggedValue(Type.FLOAT_TYPE, insn, false, value);
                case Opcodes.L2D -> new TaggedValue(Type.DOUBLE_TYPE, insn, false, value);
                case Opcodes.F2I -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord(), value);
                case Opcodes.F2L -> new TaggedValue(Type.LONG_TYPE, insn, false, value);
                case Opcodes.F2D -> new TaggedValue(Type.DOUBLE_TYPE, insn, false, value);
                case Opcodes.D2I -> new TaggedValue(Type.INT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord(), value);
                case Opcodes.D2L -> new TaggedValue(Type.LONG_TYPE, insn, false, value);
                case Opcodes.D2F -> new TaggedValue(Type.FLOAT_TYPE, insn, false, value);
                case Opcodes.I2B -> new TaggedValue(Type.BYTE_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord(), value);
                case Opcodes.I2C -> new TaggedValue(Type.CHAR_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord(), value);
                case Opcodes.I2S -> new TaggedValue(Type.SHORT_TYPE, insn, value.getType() == Type.INT_TYPE && value.isCoord(), value);
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
                     Opcodes.SALOAD -> new TaggedValue(Type.getObjectType(((TypeInsnNode) insn).desc), insn, value1.isCoord(), value1, value2); // value1 = array
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
                     Opcodes.IUSHR -> new TaggedValue(Type.INT_TYPE, insn, value1.isCoord() || value2.isCoord(), value1, value2);
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
                     Opcodes.LUSHR -> new TaggedValue(Type.LONG_TYPE, insn, false, value1, value2);
                case Opcodes.FADD,
                     Opcodes.FSUB,
                     Opcodes.FMUL,
                     Opcodes.FDIV,
                     Opcodes.FREM -> new TaggedValue(Type.FLOAT_TYPE, insn, false, value1, value2);
                case Opcodes.DADD,
                     Opcodes.DSUB,
                     Opcodes.DMUL,
                     Opcodes.DDIV,
                     Opcodes.DREM -> new TaggedValue(Type.DOUBLE_TYPE, insn, false, value1, value2);
                case Opcodes.LCMP -> new TaggedValue(Type.INT_TYPE, insn, false, value1, value2);
                case Opcodes.FCMPL,
                     Opcodes.FCMPG -> new TaggedValue(Type.FLOAT_TYPE, insn, false, value1, value2);
                case Opcodes.DCMPL,
                     Opcodes.DCMPG -> new TaggedValue(Type.DOUBLE_TYPE, insn, false, value1, value2);
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
            MethodInsnNode methodInsn = (MethodInsnNode) insn;
            MethodRef ref = new MethodRef(Type.getObjectType(methodInsn.owner),
                    insn.getOpcode() != Opcodes.INVOKESTATIC, methodInsn.name, Type.getReturnType(methodInsn.desc),
                    Type.getArgumentTypes(methodInsn.desc));
            MethodTags tags = index.getClassTags(ref.owner()).getMethod(ref);
            if (tags != null) {
                for (int i = 0; i < tags.inferredArgs.length; i++) {
                    if (tags.inferredArgs[i] == COORD) {
                        values.get(i).setCoordPropagate();
                    }
                }
            }
            return new TaggedValue(Type.getReturnType(methodInsn.desc), insn, tags != null && tags.inferredReturn == COORD,
                    values.toArray(TaggedValue[]::new));
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

        private final List<TaggedValue> propagateToSources = new ArrayList<>();
        private final Object insnOrLocal;
        private boolean isCoord;

        public TaggedValue(Type type, AbstractInsnNode insn, boolean isCoord, TaggedValue... srcs) {
            super(type);
            this.insnOrLocal = insn;
            this.isCoord = isCoord;
            this.propagateToSources.addAll(Arrays.asList(srcs));
        }

        public TaggedValue(Type type, int local, boolean isCoord, TaggedValue... srcs) {
            super(type);
            this.insnOrLocal = local;
            this.isCoord = isCoord;
            this.propagateToSources.addAll(Arrays.asList(srcs));
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

        public void setCoordPropagate() {
            this.isCoord = true;
            for (TaggedValue src : this.propagateToSources) {
                if (src.getType() == Type.INT_TYPE) {
                    src.setCoordPropagate();
                }
            }
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

    private record MethodRef(Type owner, boolean isInstance, String name, Type returnType, Type... args) {

        @Override public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            MethodRef methodRef = (MethodRef) o;
            return isInstance == methodRef.isInstance && Objects.equals(owner, methodRef.owner) && Objects.equals(name, methodRef.name)
                    && Arrays.equals(args, methodRef.args) && Objects.equals(returnType, methodRef.returnType);
        }

        @Override public int hashCode() {
            return Objects.hash(owner, isInstance, name, returnType, Arrays.hashCode(args));
        }
    }

    private record FieldRef(Type owner, String name, Type type) {
    }

    private static class MethodTags {
        private final InferredTypeTag inferredReturn;
        private final InferredTypeTag[] inferredArgs;

        private MethodTags(InferredTypeTag inferredReturn, InferredTypeTag... inferredArgs) {
            this.inferredReturn = inferredReturn;
            this.inferredArgs = inferredArgs;
        }
    }

    private record InferredType(InferredTypeTag tag, Type type) {
    }

    enum InferredTypeTag {
        NONE, COORD
    }

    private static class TaggedClassInfo {
        private final Type type;
        private final Map<MethodRef, MethodTags> methods = new HashMap<>();
        private final Map<FieldRef, InferredTypeTag> fields = new HashMap<>();

        public TaggedClassInfo(Type type) {
            this.type = type;
        }

        public void addMethod(MethodRef ref, MethodTags tags) {
            this.methods.put(ref, tags);
        }

        public MethodTags getMethod(MethodRef ref) {
            MethodTags methodTags = this.methods.get(ref);
            if (methodTags == null) {
                InferredTypeTag[] inferredArgs = new InferredTypeTag[ref.args.length + (ref.isInstance ? 1 : 0)];
                Arrays.fill(inferredArgs, NONE);
                this.methods.put(ref, methodTags = new MethodTags(NONE, inferredArgs));
            }
            return methodTags;
        }
    }

    private static class JarTagIndex {
        private final Map<Type, TaggedClassInfo> classTags = new HashMap<>();

        public void addClass(Type type, TaggedClassInfo info) {
            classTags.put(type, info);
        }

        public TaggedClassInfo getClassTags(Type owner) {
            TaggedClassInfo taggedClassInfo = classTags.get(owner);
            if (taggedClassInfo == null) {
                classTags.put(owner, taggedClassInfo = new TaggedClassInfo(owner));
            }
            return taggedClassInfo;
        }
    }
}
