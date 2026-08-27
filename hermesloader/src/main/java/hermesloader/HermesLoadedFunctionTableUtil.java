package hermesloader;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;

public final class HermesLoadedFunctionTableUtil {

    private static final DataType UINT32 = new UnsignedIntegerDataType();

    private HermesLoadedFunctionTableUtil() {
        // Utility class
    }

    public static StructureDataType createLoadedFunctionTableEntryStruct() {
        StructureDataType struct = new StructureDataType("LoadedFunctionTableEntry", 0);
        DataType pointer64 = new PointerDataType();

        struct.add(pointer64, 4, "offset", "Function offset into Loaded Function Table");
        struct.add(UINT32, 4, "paramCount", "Number of parameters for the function");
        
        return struct;
    }
}