package hermesloader;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

public final class HermesIdentifierHashesTableUtil {

    private static final DataType UINT32 = new UnsignedIntegerDataType();

    private HermesIdentifierHashesTableUtil() {
        // Utility class
    }
    
    /**
     * Creates a structure for Hermes identifier hashes table entries
     * Structure: 
     * - hash: 32 bits (4 bytes)
     * Represents the hash value of an identifier
     */
    public static StructureDataType createIdentifierHashesTableEntryStruct() {
        StructureDataType struct = new StructureDataType("IdentifierHashesTableEntry", 0);

        struct.add(UINT32, "hash", "Hash value of the identifier");
        
        return struct;
    }
    
    /**
     * Applies the identifier hashes table entry structure to the identifier hashes table memory
     */
    public static void createIdentifierHashesTableStructs(Program program, FlatProgramAPI api, Memory mem, int identifierHashesTableOffset, int identifierCount) throws Exception {
        
        StructureDataType identifierHashesTableEntryStruct = createIdentifierHashesTableEntryStruct();
        
        // Apply the struct to each identifier hashes table entry
        for (int i = 0; i < identifierCount; i++) {
            int entryOffset = identifierHashesTableOffset + (i * 4); // Each entry is 4 bytes
            
            api.createData(api.toAddr(entryOffset), identifierHashesTableEntryStruct);
            api.setPreComment(api.toAddr(entryOffset), "Identifier Hashes Table Entry " + i);
            
            Address entryAddr = api.toAddr(entryOffset);
            
            // Read the hash value
            int hashValue = mem.getInt(entryAddr);
            api.setEOLComment(entryAddr, String.format("Hash: 0x%X", hashValue));
        }
    }
}
