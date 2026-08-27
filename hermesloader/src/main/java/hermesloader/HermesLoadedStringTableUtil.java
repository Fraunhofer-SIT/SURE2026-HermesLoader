package hermesloader;


import ghidra.program.model.address.Address;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

public final class HermesLoadedStringTableUtil {

    private static final DataType UINT32 = new UnsignedIntegerDataType();

    private HermesLoadedStringTableUtil() {
        // Utility class
    }

    public static StructureDataType createLoadedStringTableEntryStruct(boolean isUTF16) {
        StructureDataType struct = new StructureDataType("LoadedStringTableEntry", 0);
        DataType base = isUTF16 ? new TerminatedUnicodeDataType() : new TerminatedStringDataType();
        DataType pointer64 = new PointerDataType(base);
        DataType boolType = new BooleanDataType();

        struct.add(pointer64, 4, "offset", "String offset into stringData");
        struct.add(boolType, 1, "isUTF16", "Indicates if the string is UTF-16 encoded");
        struct.add(UINT32, 4, "length", "Length of the string in bytes");
        
        return struct;
    }

    public static String getStringFromLoadedStringTableEntry(Program program, Address entryAddr) {
        Data entryData = program.getListing().getDataAt(entryAddr);
        if (entryData == null || !entryData.getDataType().getName().equals("LoadedStringTableEntry")) {
            throw new IllegalArgumentException("No LoadedStringTableEntry data at the specified address");
        }

        Address stringOffsetAddr = (Address) entryData.getComponent(0).getValue();

        Data stringData = program.getListing().getDataAt(stringOffsetAddr);
        if (stringData == null) {
            throw new IllegalArgumentException("No string data at the specified offset address");
        }

        Object value = stringData.getValue();
        if (value == null) {
            throw new IllegalArgumentException("String data value is null at the specified offset address");
        }
        return value.toString();

    }
}