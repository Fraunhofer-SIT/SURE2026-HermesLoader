package hermesloader.structs;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;

/**
 * Defines Ghidra DataTypes for the Hermes Array Buffer encoding.
 * These are helper factory methods used by the loader when applying
 * parsed Array Buffer segments.
 */
public final class HermesArrayBufferDataTypes {

    private static final CategoryPath CAT = new CategoryPath("/Hermes/ArrayBuffer");

    private HermesArrayBufferDataTypes() {}

    /**
     * Segment header: always represented as two bytes in memory to simplify application.
     * Byte 0: bit7=extended flag, bits6-4=tag type (mask 0x70), bits3-0=length low nibble (or high nibble when extended)
     * Byte 1: only meaningful if extended flag set (low 8 bits of length); ignored otherwise.
     */
    public static StructureDataType createSegmentHeader() {
        StructureDataType s = new StructureDataType(CAT, "ArraySegmentHeader", 0);
        s.add(ByteDataType.dataType, "tagLenHi", "bit7=extended, bits6-4=tag type, bits3-0=length nibble");
        s.add(ByteDataType.dataType, "optLenLo", "only used if extended flag set");
        return s;
    }

    public static DataType numberValueType() {
        return UnsignedLongLongDataType.dataType; // 8-byte unsigned
    }

    public static DataType longStringRefType() {
        return UnsignedIntegerDataType.dataType; // 32-bit string id
    }

    public static DataType shortStringRefType() {
        return UnsignedShortDataType.dataType; // 16-bit string id
    }

    public static DataType byteStringRefType() {
        // Ghidra treats ByteDataType as signed, but for display purposes this represents an unsigned 8-bit ID.
        return ByteDataType.dataType; // 8-bit string id (interpret as unsigned)
    }

    public static DataType integerValueType() {
        return UnsignedIntegerDataType.dataType; // 32-bit integer
    }

    /**
     * Convenience for creating an array datatype of a given primitive element.
     */
    public static ArrayDataType makeArray(DataType elem, int count) {
        int len = elem.getLength();
        return new ArrayDataType(elem, count, len);
    }
}
