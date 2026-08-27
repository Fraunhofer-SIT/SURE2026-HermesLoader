package hermesloader;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

public final class HermesStringKindsTableUtil {

    private static final DataType UINT32 = new UnsignedIntegerDataType();

    private HermesStringKindsTableUtil() {
        // Utility class
    }
    
    /**
     * Creates a structure for Hermes string kinds table entries
     * Structure: 
     * - kind: 32 bits (4 bytes)
     * Represents the type/kind of string
     */
    public static StructureDataType createStringKindsTableEntryStruct() {
        StructureDataType struct = new StructureDataType("StringKindsTableEntry", 0);

        struct.add(UINT32, "kind", "Type/kind of the string");
        
        return struct;
    }
    
    /**
     * Applies the string kinds table entry structure to the string kinds table memory
     */
    public static void createStringKindsTableStructs(Program program, FlatProgramAPI api, Memory mem, 
                                              int stringKindsTableOffset, int stringKindCount) throws Exception {
        
        StructureDataType stringKindsTableEntryStruct = createStringKindsTableEntryStruct();
        
        // Apply the struct to each string kinds table entry
        for (int i = 0; i < stringKindCount; i++) {
            int entryOffset = stringKindsTableOffset + (i * 4); // Each entry is 4 bytes
            
            api.createData(api.toAddr(entryOffset), stringKindsTableEntryStruct);
            api.setPreComment(api.toAddr(entryOffset), "String Kinds Table Entry " + i);
            
            Address entryAddr = api.toAddr(entryOffset);
            
            // Read the kind value
            int kindValue = mem.getInt(entryAddr);
            api.setEOLComment(entryAddr, String.format("Kind: 0x%X", kindValue));
        }
    }
}
