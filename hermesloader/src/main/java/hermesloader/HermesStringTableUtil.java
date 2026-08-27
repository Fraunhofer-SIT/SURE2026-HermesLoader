package hermesloader;

import java.nio.charset.StandardCharsets;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public final class HermesStringTableUtil {

    private static final DataType UINT32 = new UnsignedIntegerDataType();

    private HermesStringTableUtil() {
        // Utility class
    }
    
    /**
     * Creates a structure for Hermes string table entries
     * Structure: 
     * - isUTF16: 1 bit
     * - offset: 23 bits  
     * - length: 8 bits
     * Total: 32 bits (4 bytes)
     */
    public static StructureDataType createStringTableEntryStruct() throws InvalidDataTypeException {
        StructureDataType struct = new StructureDataType("StringTableEntry", 0);
        struct.setPackingEnabled(true);
        
        DataType boolType = new BooleanDataType();
        
        struct.addBitField(boolType, 1, "isUTF16", "Indicates if the string is UTF-16 encoded");
        struct.addBitField(UINT32, 23, "offset", "Offset to the string data in the string storage");
        struct.addBitField(UINT32, 8, "length", "Length of the string in bytes");
        
        return struct;
    }
    
    /**
     * Applies the string table entry structure to the string table memory
     */
    public static void createStringTableStructs(Program program, FlatProgramAPI api, Memory mem, 
                                              int stringTableOffset, int stringCount, int stringStorageBase, int overflowStringTableOffset) throws Exception, InvalidDataTypeException {
        
        StructureDataType stringTableEntryStruct = createStringTableEntryStruct();
        
        // Apply the struct to each string table entry
        for (int i = 0; i < stringCount; i++) {
            int entryOffset = stringTableOffset + (i * 4); // Each entry is 4 bytes
            
            api.createData(api.toAddr(entryOffset), stringTableEntryStruct);
            api.setPreComment(api.toAddr(entryOffset), "String Table Entry " + i);
            
            Address entryAddr = api.toAddr(entryOffset);
            int packedValue = mem.getInt(entryAddr);
            
            // Extract the offset bitfield (bits 1-23)
            int offsetValue = (packedValue >> 1) & 0x7FFFFF; // Shift right 1, mask 23 bits
            boolean isUTF16 = (packedValue & 0x1) != 0;
            int length = (packedValue >> 24) & 0xFF;

            if (length == 255) {
                Address targetAddr = api.toAddr(overflowStringTableOffset + (offsetValue * 8)); // Each overflow string table entry is 8 bytes 
                ReferenceManager refMgr = program.getReferenceManager();
                refMgr.addMemoryReference(entryAddr, targetAddr, RefType.DATA, SourceType.ANALYSIS, 0);
                String labelName = String.format("str_%d_%s", i, isUTF16 ? "utf16" : "utf8");
                api.setEOLComment(entryAddr, String.format("-> %s (Overflow String)", labelName));
                
            } else {
                Address targetAddr = api.toAddr(stringStorageBase + offsetValue);
                ReferenceManager refMgr = program.getReferenceManager();
                refMgr.addMemoryReference(entryAddr, targetAddr, RefType.DATA, SourceType.ANALYSIS, 0);
                String labelName = String.format("str_%d_%s", i, isUTF16 ? "utf16" : "utf8");
                api.setEOLComment(entryAddr, String.format("-> %s (%d bytes)", labelName, length));
            }
            
        }
    }
    
    /**
     * Gets the string from stringStorage for the nth string in the small string table
     * @param program The program containing the string data
     * @param mem The program memory
     * @param stringTableOffset The offset of the string table in memory
     * @param stringStorageBase The base address of the string storage area
     * @param n The index of the string to retrieve (0-based)
     * @return The string value, or null if the index is out of bounds
     * @throws CancelledException If the operation is cancelled
     */
    public static String getNthStringFromStringStorage(Program program, Memory mem, 
                                                     int stringTableOffset, int stringStorageBase, 
                                                     int n) throws CancelledException {

        return getNthStringFromStringStorage(program, mem, stringTableOffset, stringStorageBase, -1, n);
    }

    /**
     * Gets the string from string storage for the nth string table entry.
     * If the table entry length is 255, resolves data via the overflow string table.
     */
    public static String getNthStringFromStringStorage(Program program, Memory mem,
                                                     int stringTableOffset, int stringStorageBase,
                                                     int overflowStringTableOffset, int n) throws CancelledException {

        // Calculate the address of the nth string table entry
        int entryOffset = stringTableOffset + (n * 4);
        Address entryAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entryOffset);

        // Read the packed value from the string table entry
        int packedValue;
        try {
            packedValue = mem.getInt(entryAddr);
        } catch (MemoryAccessException e) {
			Msg.error(HermesStringTableUtil.class, "Failed to read string table entry at " + entryAddr);
            return null; // Memory read error
        }

        // Extract the bitfields from the packed value
        boolean isUTF16 = (packedValue & 0x1) != 0;
        int offsetValue = (packedValue >> 1) & 0x7FFFFF; // Shift right 1, mask 23 bits
        int length = (packedValue >> 24) & 0xFF;

        // Overflow entries keep the real offset/length in the overflow table.
        if (length == 255) {
            if (overflowStringTableOffset < 0) {
                Msg.error(HermesStringTableUtil.class,
                    "Overflow string table offset is required for entry " + n + " at " + entryAddr);
                return null;
            }

            Address overflowEntryAddr = program.getAddressFactory()
                .getDefaultAddressSpace()
                .getAddress(overflowStringTableOffset + (offsetValue * 8));
            try {
                offsetValue = mem.getInt(overflowEntryAddr);
                length = mem.getInt(overflowEntryAddr.add(4));
            } catch (MemoryAccessException e) {
                Msg.error(HermesStringTableUtil.class,
                    "Failed to read overflow string entry at " + overflowEntryAddr);
                return null;
            }
        }

        if (length < 0) {
            Msg.error(HermesStringTableUtil.class,
                "Invalid negative string length " + length + " for entry " + n);
            return null;
        }
        
        // Calculate the address of the string data in string storage
        int stringDataOffset = stringStorageBase + offsetValue;
        Address stringDataAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(stringDataOffset);

        
        // Read the string data from memory
        byte[] stringBytes;
        try {
            stringBytes = new byte[length];
            int bytesRead = mem.getBytes(stringDataAddr, stringBytes);
            if (bytesRead != length) {
                return null; // Failed to read all bytes
            }
        } catch (MemoryAccessException e) {
			Msg.error(HermesStringTableUtil.class, "Failed to read string data at " + stringDataAddr);
            return null; // Memory read error
        }
        
        // Convert bytes to string based on encoding
        if (isUTF16) {
            // UTF-16 encoding (little-endian)
            return new String(stringBytes, StandardCharsets.UTF_16LE);
        }
        
        // UTF-8 encoding
        return new String(stringBytes, StandardCharsets.UTF_8);
    }
}
