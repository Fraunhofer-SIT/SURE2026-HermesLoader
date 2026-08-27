package hermesloader;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

public final class HermesOverflowStringTableUtil {

    private static final DataType UINT32 = new UnsignedIntegerDataType();

    private HermesOverflowStringTableUtil() {
        // Utility class
    }
    
    /**
     * Creates a structure for Hermes overflow string table entries
     * Structure: 
     * - offset: 32 bits (4 bytes)
     * - length: 32 bits (4 bytes)
     * Total: 64 bits (8 bytes)
     */
    public static StructureDataType createOverflowStringTableEntryStruct() {
        StructureDataType struct = new StructureDataType("OverflowStringTableEntry", 0);

        struct.add(UINT32, "offset", "Offset to the string data in the string storage");
        struct.add(UINT32, "length", "Length of the string in bytes");
        
        return struct;
    }
    
    /**
     * Applies the overflow string table entry structure to the overflow string table memory
     */
    public static void createOverflowStringTableStructs(Program program, FlatProgramAPI api, Memory mem, 
                                              int overflowStringTableOffset, int overflowStringCount, int stringStorageBase) throws Exception {
        
        StructureDataType overflowStringTableEntryStruct = createOverflowStringTableEntryStruct();
        
        // Apply the struct to each overflow string table entry
        for (int i = 0; i < overflowStringCount; i++) {
            int entryOffset = overflowStringTableOffset + (i * 8); // Each entry is 8 bytes
            
            api.createData(api.toAddr(entryOffset), overflowStringTableEntryStruct);
            api.setPreComment(api.toAddr(entryOffset), "Overflow String Table Entry " + i);
            
            Address entryAddr = api.toAddr(entryOffset);
            
            // Read the offset (first 4 bytes)
            int offsetValue = mem.getInt(entryAddr);
            
            // Read the length (next 4 bytes)
            int length = mem.getInt(entryAddr.add(4));
            
            Address targetAddr = api.toAddr(stringStorageBase + offsetValue);
            ReferenceManager refMgr = program.getReferenceManager();
            refMgr.addMemoryReference(entryAddr, targetAddr, RefType.DATA, SourceType.ANALYSIS, 0);
            String labelName = String.format("overflow_str_%d", i);
            api.setEOLComment(entryAddr, String.format("-> %s (%d bytes)", labelName, length));
        }
    }
}
