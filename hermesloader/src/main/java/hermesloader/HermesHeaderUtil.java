package hermesloader;

import java.io.InputStream;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

public class HermesHeaderUtil {
    public static void createHermesHeader(Program program, FlatProgramAPI api, Memory mem, InputStream inputStreamForMem, TaskMonitor monitor, int byteCounter) throws Exception {
        mem.createInitializedBlock("Header", api.toAddr(byteCounter), inputStreamForMem, 128, monitor, false);
        DataUtilities.createData(program, api.toAddr(byteCounter), ghidra.app.util.bin.StructConverter.QWORD, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        Data magicBytes = DataUtilities.getDataAtAddress(program, api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Hermes Magic Byte " + magicBytes.toString());
        byteCounter+=8;
        // 1. version (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int version = mem.getInt(api.toAddr(byteCounter), false);
        api.setPreComment(api.toAddr(byteCounter), "Hermes Bytecode Version: " + version);
        byteCounter += 4;
        // 2. sourceHash (20 bytes, u8 array)
        api.setPreComment(api.toAddr(byteCounter), "Source Hash Byte");
        for (int i = 0; i < 20; i++) {
            DataUtilities.createData(program, api.toAddr(byteCounter), ghidra.app.util.bin.StructConverter.BYTE, 1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
            byteCounter += 1;
        }
        // 3. fileLength (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int fileLength = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "File Length: " + fileLength);
        byteCounter += 4;
        // 4. globalCodeIndex (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int globalCodeIndex = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Global Code Index: " + globalCodeIndex);
        byteCounter += 4;
        // 5. functionCount (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int functionCount = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Function Count: " + functionCount);
        byteCounter += 4;
        // 6. stringKindCount (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int stringKindCount = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "String Kind Count: " + stringKindCount);
        byteCounter += 4;
        // 7. identifierCount (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int identifierCount = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Identifier Count: " + identifierCount);
        byteCounter += 4;
        // 8. stringCount (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int stringCount = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "String Count: " + stringCount);
        byteCounter += 4;
        // 9. overflowStringCount (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int overflowStringCount = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Overflow String Count: " + overflowStringCount);
        byteCounter += 4;
        // 10. stringStorageSize (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int stringStorageSize = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "String Storage Size: " + stringStorageSize);
        byteCounter += 4;
        // 11. bigIntCount (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int bigIntCount = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "BigInt Count: " + bigIntCount);
        byteCounter += 4;
        // 12. bigIntStorageSize (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int bigIntStorageSize = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "BigInt Storage Size: " + bigIntStorageSize);
        byteCounter += 4;
        // 13. regExpCount (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int regExpCount = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "RegExp Count: " + regExpCount);
        byteCounter += 4;
        // 14. regExpStorageSize (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int regExpStorageSize = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "RegExp Storage Size: " + regExpStorageSize);
        byteCounter += 4;
        // 15. arrayBufferSize (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int arrayBufferSize = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Array Buffer Size: " + arrayBufferSize);
        byteCounter += 4;
        // 16. objKeyBufferSize (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int objKeyBufferSize = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Object Key Buffer Size: " + objKeyBufferSize);
        byteCounter += 4;
        // 17. objValueBufferSize (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int objValueBufferSize = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Object Value Buffer Size: " + objValueBufferSize);
        byteCounter += 4;
        // 18. segmentID (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int segmentID = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Segment ID: " + segmentID);
        byteCounter += 4;
        // 19. cjsModuleCount (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int cjsModuleCount = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "CJS Module Count: " + cjsModuleCount);
        byteCounter += 4;
        // 20. functionSourceCount (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int functionSourceCount = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Function Source Count: " + functionSourceCount);
        byteCounter += 4;
        // 21. debugInfoOffset (u32)
        DataUtilities.createData(program, api.toAddr(byteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        int debugInfoOffset = mem.getInt(api.toAddr(byteCounter));
        api.setPreComment(api.toAddr(byteCounter), "Debug Info Offset: " + debugInfoOffset);
        byteCounter += 4;
        // 22. options (BytecodeOptions, special handling may be needed)
        // Placeholder for options field
        DataUtilities.createData(program, api.toAddr(byteCounter), ghidra.app.util.bin.StructConverter.BYTE, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        api.setPreComment(api.toAddr(byteCounter), "Options (BytecodeOptions, structure TBD)");
        byteCounter += 1;
        api.setPreComment(api.toAddr(byteCounter), "Padding");
        for (int i = 0; i < 19; i++) {
            DataUtilities.createData(program, api.toAddr(byteCounter), ghidra.app.util.bin.StructConverter.BYTE, 1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
            byteCounter += 1;
        }
    }
}
