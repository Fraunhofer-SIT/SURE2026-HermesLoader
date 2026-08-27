package hermesloader.parser;

import java.util.List;

// Ghidra imports only used by the overloaded method that materializes DataTypes
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.util.CodeUnitInsertionException;
import hermesloader.structs.HermesArrayBufferDataTypes;
import ghidra.util.Msg;

public class HermesArrayBufferParser {

    /**
     * Result container: the absolute next index into the original storage
     * after parsing, plus the list of parsed elements.
     */
    public static class ParsedArrayBufferResult {
        public final int nextIndex;
        public final List<ArrayBuffer> arrays;

        public ParsedArrayBufferResult(int nextIndex, List<ArrayBuffer> arrays) {
            this.nextIndex = nextIndex;
            this.arrays = arrays;
        }
    }

    public static class ArrayBuffer {
        public final int arrayType;
        public final List<ArrayType> array;

        public ArrayBuffer(int arrayType, List<ArrayType> array) {
            this.arrayType = arrayType;
            this.array = array;
        }
    }


    /* ---------- Variant type hierarchy ---------- */

    public interface ArrayType {}

    public static class NullValue implements ArrayType {
        @Override public String toString() { return "Null"; }
    }

    public static class TrueValue implements ArrayType {
        public final boolean value = true;
        @Override public String toString() { return "True"; }
    }

    public static class FalseValue implements ArrayType {
        public final boolean value = false;
        @Override public String toString() { return "False"; }
    }

    public static class NumberValue implements ArrayType {
        // Raw 64-bit little-endian integer.
        public final long value;
        public NumberValue(long value) { this.value = value; }
        @Override public String toString() { return "Number(u64=" + value + ")"; }
    }

    public static class LongStringValue implements ArrayType {
        public final long value; // u32 stored in a Java long for unsigned safety.
        public LongStringValue(long value) { this.value = value & 0xFFFFFFFFL; }
        @Override public String toString() { return "LongStringRef(id=" + value + ")"; }
    }

    public static class ShortStringValue implements ArrayType {
        public final int value; // u16
        public ShortStringValue(int value) { this.value = value & 0xFFFF; }
        @Override public String toString() { return "ShortStringRef(id=" + value + ")"; }
    }

    public static class ByteStringValue implements ArrayType {
        public final int value; // u8
        public ByteStringValue(int value) { this.value = value & 0xFF; }
        @Override public String toString() { return "ByteStringRef(id=" + value + ")"; }
    }

    public static class IntegerValue implements ArrayType {
        public final long value; // u32
        public IntegerValue(long value) { this.value = value & 0xFFFFFFFFL; }
        @Override public String toString() { return "Integer(u32=" + value + ")"; }
    }

    /* ---------- Tag constants (upper nibble in 0x70 mask) ---------- */

    private static final int NULL_TAG         = 0 << 4;
    private static final int TRUE_TAG         = 1 << 4;
    private static final int FALSE_TAG        = 2 << 4;
    private static final int NUMBER_TAG       = 3 << 4;
    private static final int LONG_STRING_TAG  = 4 << 4;
    private static final int SHORT_STRING_TAG = 5 << 4;
    private static final int BYTE_STRING_TAG  = 6 << 4;
    private static final int INTEGER_TAG      = 7 << 4;
  
    /**
     * Overloaded helper that BOTH parses the array buffer and applies Ghidra DataTypes
     * directly into the program listing.  The memory block containing 'storage' must have
     * already been created at 'baseAddress'.  The first byte of 'storage' corresponds to
     * baseAddress + idx.
     *
     * @param storage     Raw array buffer bytes
     * @param api         FlatProgramAPI for creating data & comments
     * @param mem         Program memory (for bounds / references if needed)
     * @param baseAddress Address in program where storage[0] is mapped
     */
    public static void getArrayBuffer(byte[] storage, FlatProgramAPI api, Memory mem, Address baseAddress) {
        final int bufSize = storage.length;
        int off = 0;
        final StructureDataType extendedHeaderDt = HermesArrayBufferDataTypes.createSegmentHeader();

        while (off < bufSize) {
            int segmentStart = off;
            int first = storage[off] & 0xFF;
            boolean extended = (first & 0x80) != 0;
            int tagType = first & 0x70; // upper nibble per format
            long declaredCount;
            int headerLen;

            if (extended) {
                if (off + 2 > bufSize) {
                    // Incomplete extended header at end of buffer.
                    api.setPreComment(baseAddress.add(off), "Truncated extended header");
                    break;
                }
                int lenLow = storage[off + 1] & 0xFF;
                declaredCount = ((first & 0x0F) << 8) | lenLow; // 12-bit count
                headerLen = 2;
            } else {
                declaredCount = (first & 0x0F);
                headerLen = 1;
            }

            Address headerAddr = baseAddress.add(off);
            try {
                if (extended) {
                    DataUtilities.createData(api.getCurrentProgram(), headerAddr, extendedHeaderDt, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                } else {
                    DataUtilities.createData(api.getCurrentProgram(), headerAddr, ByteDataType.dataType, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                }
            } catch (CodeUnitInsertionException t) {
                Msg.debug(HermesArrayBufferParser.class, "Failed to create segment header at " + headerAddr + ": " + t.getMessage());
                break;
            }

            off += headerLen; // move past header

            // Determine payload element size & DataType
            int elemSize;
            DataType elemType;
            boolean logical = false; // tags that have no payload bytes (NULL/TRUE/FALSE)
            switch (tagType) {
                case NULL_TAG, TRUE_TAG, FALSE_TAG -> { logical = true; elemSize = 0; elemType = null; }
                case NUMBER_TAG -> { elemSize = 8; elemType = HermesArrayBufferDataTypes.numberValueType(); }
                case LONG_STRING_TAG -> { elemSize = 4; elemType = HermesArrayBufferDataTypes.longStringRefType(); }
                case SHORT_STRING_TAG -> { elemSize = 2; elemType = HermesArrayBufferDataTypes.shortStringRefType(); }
                case BYTE_STRING_TAG -> { elemSize = 1; elemType = HermesArrayBufferDataTypes.byteStringRefType(); }
                case INTEGER_TAG -> { elemSize = 4; elemType = HermesArrayBufferDataTypes.integerValueType(); }
                default -> {
                    api.setPreComment(headerAddr, "Unknown tagType=0x" + Integer.toHexString(tagType));
                    return; // Stop materialization to avoid misinterpretation
                }
            }

            if (logical) {
                api.setPreComment(headerAddr, String.format("ArrayBuffer Segment Header: tag=%s count=%d (no payload)", tagName(tagType), declaredCount));
                // Nothing more to consume. Guard: ensure forward progress happened (headerLen>0)
                if (off <= segmentStart) {
                    Msg.debug(HermesArrayBufferParser.class, "No forward progress on logical segment at off=" + segmentStart);
                    break;
                }
                continue;
            }

            long bytesRemaining = bufSize - off;
            long requestedBytes = declaredCount * elemSize;
            boolean truncated = false;
            long elementCount = declaredCount;
            long actualBytes;
            if (requestedBytes > bytesRemaining) {
                truncated = true;
                elementCount = bytesRemaining / elemSize; // clamp
                actualBytes = elementCount * elemSize;
            } else {
                actualBytes = requestedBytes;
            }

            if (elementCount == 0) {
                api.setPreComment(headerAddr, String.format("ArrayBuffer Segment Header: tag=%s declared=%d TRUNCATED(no bytes)", tagName(tagType), declaredCount));
                break; // can't interpret further
            }

            api.setPreComment(headerAddr, String.format("ArrayBuffer Segment Header: tag=%s declared=%d actual=%d%s", tagName(tagType), declaredCount, elementCount, truncated ? " (TRUNCATED)" : ""));
            

            Address elemAddr = baseAddress.add(off);
            try {
                ArrayDataType arrDt = new ArrayDataType(elemType, (int)elementCount, elemSize);
                DataUtilities.createData(api.getCurrentProgram(), elemAddr, arrDt, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                api.setPreComment(elemAddr, String.format("Segment Elements: %s count=%d elemSize=%d totalBytes=%d", tagName(tagType), elementCount, elemSize, actualBytes));
            } catch (CodeUnitInsertionException t) {
                Msg.debug(HermesArrayBufferParser.class, "Failed to create element array at " + elemAddr + ": " + t.getMessage());
                break;
            }

            off += (int)actualBytes; // consume payload bytes

            if (off <= segmentStart) { // forward progress guard
                Msg.debug(HermesArrayBufferParser.class, "No forward progress at segment start=" + segmentStart + "; aborting to prevent infinite loop");
                break;
            }

            if (truncated) {
                // Remaining tail incomplete; stop parsing further segments.
                break;
            }
        }
    }

    private static String tagName(int tagType) {
        return switch (tagType) {
            case NULL_TAG -> "Null";
            case TRUE_TAG -> "True";
            case FALSE_TAG -> "False";
            case NUMBER_TAG -> "Number";
            case LONG_STRING_TAG -> "LongStringRef";
            case SHORT_STRING_TAG -> "ShortStringRef";
            case BYTE_STRING_TAG -> "ByteStringRef";
            case INTEGER_TAG -> "Integer";
            default -> "Unknown";
        };
    }
}