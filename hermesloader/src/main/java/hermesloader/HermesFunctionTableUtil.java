package hermesloader;

import java.io.InputStream;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

public final class HermesFunctionTableUtil {

    private static final DataType UINT32 = new UnsignedIntegerDataType();

    private HermesFunctionTableUtil() {
        // Utility class
    }
    
    /**
     * Creates a structure for Hermes function table entries
     * Structure: 16 bytes per function entry with specific bit fields
     */
    public static StructureDataType createFunctionTableEntryStruct() throws InvalidDataTypeException {
        StructureDataType struct = new StructureDataType("FunctionTableEntry", 0);
        struct.setPackingEnabled(true);
        
        // Add fields with specific bit sizes as per Hermes specification
        // First 32-bit word: offset (25 bits) + paramCount (7 bits)
        struct.addBitField(UINT32, 25, "offset", "Function offset in bytecode");
        struct.addBitField(UINT32, 7, "paramCount", "Number of parameters");
        
        // Second 32-bit word: bytecodeSizeInBytes (15 bits) + functionName (17 bits)
        struct.addBitField(UINT32, 15, "bytecodeSizeInBytes", "Function bytecode size in bytes");
        struct.addBitField(UINT32, 17, "functionName", "Function name index");
        
        // Third 32-bit word: infoOffset (25 bits) + frameSize (7 bits)
        struct.addBitField(UINT32, 25, "infoOffset", "Function info offset");
        struct.addBitField(UINT32, 7, "frameSize", "Function frame size");
        
        // Fourth 32-bit word: environmentSize (8 bits) + highestReadCacheIndex (8 bits) + highestWriteCacheIndex (8 bits) + flags (8 bits)
        struct.addBitField(UINT32, 8, "environmentSize", "Environment size");
        struct.addBitField(UINT32, 8, "highestReadCacheIndex", "Highest read cache index");
        struct.addBitField(UINT32, 8, "highestWriteCacheIndex", "Highest write cache index");
        struct.addBitField(UINT32, 8, "flags", "Function flags");
        
        return struct;
    }
    
    public static void createHermesFunctionTable(Program program, FlatProgramAPI api, Memory mem, InputStream inputStreamForMem, TaskMonitor monitor, int functionCount, int byteCounter) throws Exception {
        mem.createInitializedBlock("Function Table", api.toAddr(byteCounter), inputStreamForMem, functionCount * 16, monitor, false);
        
        // Apply function table structure if we know the format
        StructureDataType functionTableEntryStruct = createFunctionTableEntryStruct();
        
        // Apply the struct to each function table entry
        for (int i = 0; i < functionCount; i++) {
            int entryOffset = byteCounter + (i * 16); // Each entry is 16 bytes
            
            api.createData(api.toAddr(entryOffset), functionTableEntryStruct);
            api.setPreComment(api.toAddr(entryOffset), "Function Table Entry " + i);
        }
    }
}
