package hermesloader.structs;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;

public final class HermesFunctionSourceStruct {

    private static final DataType UINT32 = new UnsignedIntegerDataType();

    private HermesFunctionSourceStruct() {
        // Utility class
    }
    
    /**
     * Creates a structure for Hermes function source table entries
     * Structure: 8 bytes per function source entry
     */
    public static StructureDataType createFunctionSourceTableEntryStruct() {
        StructureDataType struct = new StructureDataType("FunctionSourceTableEntry", 0);

        struct.add(UINT32, 4, "function_id", "Function identifier");
        struct.add(UINT32, 4, "string_id", "Source String identifier");

        return struct;
    }
}