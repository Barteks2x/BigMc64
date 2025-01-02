package io.github.barteks2x.bigmc64;

import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;

public class AsmUtil {

    public static Type arrayTypeFromOperand(int operand) {
        return switch (operand) {
            case T_INT -> Type.getType(int[].class);
            case T_LONG -> Type.getType(long[].class);
            case T_FLOAT -> Type.getType(float[].class);
            case T_DOUBLE -> Type.getType(double[].class);
            case T_BYTE -> Type.getType(byte[].class);
            case T_SHORT -> Type.getType(short[].class);
            case T_CHAR -> Type.getType(char[].class);
            case T_BOOLEAN -> Type.getType(boolean[].class);
            default -> throw new IllegalStateException("Unexpected value: " + operand);
        };
    }
    public static Type getInsnNodeOperandType(AbstractInsnNode insnNode) {
        return switch (insnNode.getOpcode()) {
            // No arguments or handled differently
            case NOP,
                 POP,
                 POP2,
                 DUP,
                 DUP_X1,
                 DUP_X2,
                 DUP2,
                 DUP2_X1,
                 DUP2_X2,
                 SWAP,
                 RETURN -> Type.VOID_TYPE;

            // Field operations
            case GETSTATIC,
                 PUTSTATIC,
                 GETFIELD,
                 PUTFIELD -> Type.getType(((FieldInsnNode) insnNode).desc);

            // Method invocations
            case INVOKEVIRTUAL,
                 INVOKESPECIAL,
                 INVOKESTATIC,
                 INVOKEINTERFACE -> Type.getReturnType(((MethodInsnNode) insnNode).desc);

            case INVOKEDYNAMIC -> throw new IllegalArgumentException("invokedynamic is not supported");

            // Type and array operations
            case NEW,
                 CHECKCAST,
                 INSTANCEOF -> Type.getObjectType(((TypeInsnNode) insnNode).desc);
            case NEWARRAY -> Type.getType(((TypeInsnNode) insnNode).desc);
            case ANEWARRAY -> Type.getType(Object[].class);

            // Single argument
            case ACONST_NULL -> Type.getType(Object.class);
            case BIPUSH,
                 SIPUSH -> Type.INT_TYPE;
            case LDC -> Type.getType(((LdcInsnNode) insnNode).cst.getClass());

            // Integers
            case ILOAD,
                 ISTORE,
                 IADD,
                 ISUB,
                 IMUL,
                 IDIV,
                 IREM,
                 ISHL,
                 ISHR,
                 IUSHR,
                 IAND,
                 IOR,
                 IXOR,
                 INEG,
                 IINC -> Type.INT_TYPE;

            // Longs
            case LLOAD,
                 LSTORE,
                 LADD,
                 LSUB,
                 LMUL,
                 LDIV,
                 LREM,
                 LSHL,
                 LSHR,
                 LUSHR,
                 LAND,
                 LOR,
                 LXOR,
                 LNEG -> Type.LONG_TYPE;

            // Floats
            case FLOAD,
                 FSTORE,
                 FADD,
                 FSUB,
                 FMUL,
                 FDIV,
                 FREM,
                 FNEG -> Type.FLOAT_TYPE;

            // Doubles
            case DLOAD,
                 DSTORE,
                 DADD,
                 DSUB,
                 DMUL,
                 DDIV,
                 DREM,
                 DNEG -> Type.DOUBLE_TYPE;

            // Objects
            case ALOAD,
                 ASTORE -> Type.getType(Object.class);

            // Arrays
            case IALOAD,
                 IASTORE -> Type.INT_TYPE;
            case LALOAD,
                 LASTORE -> Type.LONG_TYPE;
            case FALOAD,
                 FASTORE -> Type.FLOAT_TYPE;
            case DALOAD,
                 DASTORE -> Type.DOUBLE_TYPE;
            case AALOAD,
                 AASTORE -> Type.getType(Object.class);
            case BALOAD,
                 BASTORE -> Type.BYTE_TYPE;
            case CALOAD,
                 CASTORE -> Type.CHAR_TYPE;
            case SALOAD,
                 SASTORE -> Type.SHORT_TYPE;

            // Comparisons
            case LCMP,
                 FCMPL,
                 FCMPG,
                 DCMPL,
                 DCMPG -> Type.INT_TYPE;

            // Conversions
            case I2L -> Type.LONG_TYPE;
            case I2F -> Type.FLOAT_TYPE;
            case I2D -> Type.DOUBLE_TYPE;
            case L2I -> Type.INT_TYPE;
            case L2F -> Type.FLOAT_TYPE;
            case L2D -> Type.DOUBLE_TYPE;
            case F2I -> Type.INT_TYPE;
            case F2L -> Type.LONG_TYPE;
            case F2D -> Type.DOUBLE_TYPE;
            case D2I -> Type.INT_TYPE;
            case D2L -> Type.LONG_TYPE;
            case D2F -> Type.FLOAT_TYPE;
            case I2B -> Type.BYTE_TYPE;
            case I2C -> Type.CHAR_TYPE;
            case I2S -> Type.SHORT_TYPE;

            default -> throw new IllegalArgumentException("Unsupported opcode: " + insnNode.getOpcode());
        };
    }

    public static String opcodeToString(int opcode) {
        return switch (opcode) {
            case NOP -> "NOP";
            case ACONST_NULL -> "ACONST_NULL";
            case ICONST_M1 -> "ICONST_M1";
            case ICONST_0 -> "ICONST_0";
            case ICONST_1 -> "ICONST_1";
            case ICONST_2 -> "ICONST_2";
            case ICONST_3 -> "ICONST_3";
            case ICONST_4 -> "ICONST_4";
            case ICONST_5 -> "ICONST_5";
            case LCONST_0 -> "LCONST_0";
            case LCONST_1 -> "LCONST_1";
            case FCONST_0 -> "FCONST_0";
            case FCONST_1 -> "FCONST_1";
            case FCONST_2 -> "FCONST_2";
            case DCONST_0 -> "DCONST_0";
            case DCONST_1 -> "DCONST_1";
            case BIPUSH -> "BIPUSH";
            case SIPUSH -> "SIPUSH";
            case LDC -> "LDC";

            // Loads
            case ILOAD -> "ILOAD";
            case LLOAD -> "LLOAD";
            case FLOAD -> "FLOAD";
            case DLOAD -> "DLOAD";
            case ALOAD -> "ALOAD";
            case IALOAD -> "IALOAD";
            case LALOAD -> "LALOAD";
            case FALOAD -> "FALOAD";
            case DALOAD -> "DALOAD";
            case AALOAD -> "AALOAD";
            case BALOAD -> "BALOAD";
            case CALOAD -> "CALOAD";
            case SALOAD -> "SALOAD";

            // Stores
            case ISTORE -> "ISTORE";
            case LSTORE -> "LSTORE";
            case FSTORE -> "FSTORE";
            case DSTORE -> "DSTORE";
            case ASTORE -> "ASTORE";
            case IASTORE -> "IASTORE";
            case LASTORE -> "LASTORE";
            case FASTORE -> "FASTORE";
            case DASTORE -> "DASTORE";
            case AASTORE -> "AASTORE";
            case BASTORE -> "BASTORE";
            case CASTORE -> "CASTORE";
            case SASTORE -> "SASTORE";

            // Stack
            case POP -> "POP";
            case POP2 -> "POP2";
            case DUP -> "DUP";
            case DUP_X1 -> "DUP_X1";
            case DUP_X2 -> "DUP_X2";
            case DUP2 -> "DUP2";
            case DUP2_X1 -> "DUP2_X1";
            case DUP2_X2 -> "DUP2_X2";
            case SWAP -> "SWAP";

            // Arithmetic
            case IADD -> "IADD";
            case LADD -> "LADD";
            case FADD -> "FADD";
            case DADD -> "DADD";
            case ISUB -> "ISUB";
            case LSUB -> "LSUB";
            case FSUB -> "FSUB";
            case DSUB -> "DSUB";
            case IMUL -> "IMUL";
            case LMUL -> "LMUL";
            case FMUL -> "FMUL";
            case DMUL -> "DMUL";
            case IDIV -> "IDIV";
            case LDIV -> "LDIV";
            case FDIV -> "FDIV";
            case DDIV -> "DDIV";
            case IREM -> "IREM";
            case LREM -> "LREM";
            case FREM -> "FREM";
            case DREM -> "DREM";
            case INEG -> "INEG";
            case LNEG -> "LNEG";
            case FNEG -> "FNEG";
            case DNEG -> "DNEG";
            case ISHL -> "ISHL";
            case LSHL -> "LSHL";
            case ISHR -> "ISHR";
            case LSHR -> "LSHR";
            case IUSHR -> "IUSHR";
            case LUSHR -> "LUSHR";
            case IAND -> "IAND";
            case LAND -> "LAND";
            case IOR -> "IOR";
            case LOR -> "LOR";
            case IXOR -> "IXOR";
            case LXOR -> "LXOR";
            case IINC -> "IINC";

            // Conversions
            case I2L -> "I2L";
            case I2F -> "I2F";
            case I2D -> "I2D";
            case L2I -> "L2I";
            case L2F -> "L2F";
            case L2D -> "L2D";
            case F2I -> "F2I";
            case F2L -> "F2L";
            case F2D -> "F2D";
            case D2I -> "D2I";
            case D2L -> "D2L";
            case D2F -> "D2F";
            case I2B -> "I2B";
            case I2C -> "I2C";
            case I2S -> "I2S";

            // Comparisons
            case LCMP -> "LCMP";
            case FCMPL -> "FCMPL";
            case FCMPG -> "FCMPG";
            case DCMPL -> "DCMPL";
            case DCMPG -> "DCMPG";

            // Control
            case IFEQ -> "IFEQ";
            case IFNE -> "IFNE";
            case IFLT -> "IFLT";
            case IFGE -> "IFGE";
            case IFGT -> "IFGT";
            case IFLE -> "IFLE";
            case IF_ICMPEQ -> "IF_ICMPEQ";
            case IF_ICMPNE -> "IF_ICMPNE";
            case IF_ICMPLT -> "IF_ICMPLT";
            case IF_ICMPGE -> "IF_ICMPGE";
            case IF_ICMPGT -> "IF_ICMPGT";
            case IF_ICMPLE -> "IF_ICMPLE";
            case IF_ACMPEQ -> "IF_ACMPEQ";
            case IF_ACMPNE -> "IF_ACMPNE";
            case GOTO -> "GOTO";
            case JSR -> "JSR";
            case RET -> "RET";
            case TABLESWITCH -> "TABLESWITCH";
            case LOOKUPSWITCH -> "LOOKUPSWITCH";
            case IRETURN -> "IRETURN";
            case LRETURN -> "LRETURN";
            case FRETURN -> "FRETURN";
            case DRETURN -> "DRETURN";
            case ARETURN -> "ARETURN";
            case RETURN -> "RETURN";
            case GETSTATIC -> "GETSTATIC";
            case PUTSTATIC -> "PUTSTATIC";
            case GETFIELD -> "GETFIELD";
            case PUTFIELD -> "PUTFIELD";
            case INVOKEVIRTUAL -> "INVOKEVIRTUAL";
            case INVOKESPECIAL -> "INVOKESPECIAL";
            case INVOKESTATIC -> "INVOKESTATIC";
            case INVOKEINTERFACE -> "INVOKEINTERFACE";
            case INVOKEDYNAMIC -> "INVOKEDYNAMIC";
            case NEW -> "NEW";
            case NEWARRAY -> "NEWARRAY";
            case ANEWARRAY -> "ANEWARRAY";
            case ARRAYLENGTH -> "ARRAYLENGTH";
            case ATHROW -> "ATHROW";
            case CHECKCAST -> "CHECKCAST";
            case INSTANCEOF -> "INSTANCEOF";
            case MONITORENTER -> "MONITORENTER";
            case MONITOREXIT -> "MONITOREXIT";
            case MULTIANEWARRAY -> "MULTIANEWARRAY";
            case IFNULL -> "IFNULL";
            case IFNONNULL -> "IFNONNULL";
            default -> throw new IllegalArgumentException("Illegal opcode: " + opcode);
        };
    }

    public static int intToLongOpcode(int opcode) {
        return switch(opcode) {
            case IADD -> LADD;
            case ISUB -> LSUB;
            case IMUL -> LMUL;
            case IDIV -> LDIV;
            case IREM -> LREM;
            case ISHL -> LSHL;
            case ISHR -> LSHR;
            case IUSHR -> LUSHR;
            case IAND -> LAND;
            case IOR -> LOR;
            case IXOR -> LXOR;
            case INEG -> LNEG;
            case I2L -> NOP;
            case ISTORE -> LSTORE;
            case ILOAD -> LLOAD;
            case IRETURN -> LRETURN;
            case IALOAD -> LALOAD;
            case IASTORE -> LASTORE;
            case IINC -> throw new IllegalArgumentException("Cannot convert iinc");
            default -> throw new IllegalArgumentException("Cannot convert " + opcodeToString(opcode) + " to long operation");
        };
    }
}

