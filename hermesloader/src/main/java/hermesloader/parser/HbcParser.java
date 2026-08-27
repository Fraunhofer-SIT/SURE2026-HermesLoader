package hermesloader.parser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import hermesloader.parser.HbcBinaryStructs.HbcString;

public class HbcParser {

    private static void printUsage() {
        System.err.println("Usage: HbcParser [--stdin] [input-file]");
    }

    public static HbcBinaryStructs.DebugInfoHeader readDebugInfo(byte[] data) {
        BitBufferReader reader = new BitBufferReader(data);
        return new HbcBinaryStructs.DebugInfoHeader(reader);
    }

    public static HbcBinaryStructs.BytecodeFile readHbcFile(byte[] data) {
        BitBufferReader reader = new BitBufferReader(data);

        // visit header
        HbcBinaryStructs.BytecodeFileHeader bytecodeFileHeader = new HbcBinaryStructs.BytecodeFileHeader(reader);

        // visit function_headers
        List<HbcBinaryStructs.FunctionInfo> functions = new ArrayList<>();
        for (int i = 0; i < bytecodeFileHeader.functionCount; i++) {
            HbcBinaryStructs.SmallFuncHeader smallFuncHeader = new HbcBinaryStructs.SmallFuncHeader(reader);
            HbcBinaryStructs.FuncHeader funcHeader = null;

            // check if the SmallFuncHeader is missing info that we must get from the normal function at offset
            if (((smallFuncHeader.flags >> 5) & 1) != 0) {
                int largeOffset = (smallFuncHeader.infoOffset << 16) | smallFuncHeader.offset;
                BitBufferReader funcReader = new BitBufferReader(data, largeOffset, 0);
                funcHeader = new HbcBinaryStructs.FuncHeader(funcReader);
            }
            functions.add(new HbcBinaryStructs.FunctionInfo(smallFuncHeader, funcHeader));
        }

        // visit string_kinds
        List<HbcBinaryStructs.StringKind> stringKinds = new ArrayList<>();
        for (int i = 0; i < bytecodeFileHeader.stringKindCount; i++) {
            stringKinds.add(new HbcBinaryStructs.StringKind(reader));
        }

        // visit identifier_hashes
        List<HbcBinaryStructs.IdentifierHash> identifierHashes = new ArrayList<>();
        for (int i = 0; i < bytecodeFileHeader.identifierCount; i++) {
            identifierHashes.add(new HbcBinaryStructs.IdentifierHash(reader));
        }

        // visit small_string_table
        List<HbcBinaryStructs.SmallStringTableEntry> smallStringTable = new ArrayList<>();
        for (int i = 0; i < bytecodeFileHeader.stringCount; i++) {
            smallStringTable.add(new HbcBinaryStructs.SmallStringTableEntry(reader));
        }

        // visit overflow_string_table
        List<HbcBinaryStructs.OverflowStringTableEntry> overflowStringTable = new ArrayList<>();
        for (int i = 0; i < bytecodeFileHeader.overflowStringCount; i++) {
            overflowStringTable.add(new HbcBinaryStructs.OverflowStringTableEntry(reader));
        }

        // visit string_storage
        List<HbcBinaryStructs.StringStorageEntry> stringStorage = new ArrayList<>();
        for (int i = 0; i < bytecodeFileHeader.stringStorageSize; i++) {
            stringStorage.add(new HbcBinaryStructs.StringStorageEntry(reader));
        }

        int debugInfoOffset = bytecodeFileHeader.debugInfoOffset;
        if (debugInfoOffset < 0 || debugInfoOffset >= data.length) {
            throw new IllegalArgumentException("debugInfoOffset out of bounds: " + debugInfoOffset + " (file size: " + data.length + ")");
        }
        byte[] debuginfoData = new byte[data.length - debugInfoOffset];
        System.arraycopy(data, debugInfoOffset, debuginfoData, 0, debuginfoData.length);
        HbcBinaryStructs.DebugInfoHeader bytecodeFileDebugInfo = readDebugInfo(debuginfoData);

        HbcBinaryStructs.BytecodeFile bytecodeFile = new HbcBinaryStructs.BytecodeFile(
            bytecodeFileHeader,
            functions,
            bytecodeFileDebugInfo,
            stringKinds,
            identifierHashes,
            smallStringTable,
            overflowStringTable,
            stringStorage
        );

        return bytecodeFile;
    }

    public static List<HbcString> getAllStrings(HbcBinaryStructs.BytecodeFile bytecodeFile) {
        List<HbcString> strings = new ArrayList<>();

        for (int i = 0; i < bytecodeFile.bytecodeFileHeader.stringCount; i++) {
            StringBuilder stringValue = new StringBuilder();
            int offset;
            int length = bytecodeFile.smallStringTable.get(i).length;
            boolean isUTF16 = bytecodeFile.smallStringTable.get(i).isUTF16;

            if (length == 255) {
                // overflow string, get length and offset from overflow table
                int offsetToOverflowTable = bytecodeFile.smallStringTable.get(i).offset;
                offset = bytecodeFile.overflowStringTable.get(offsetToOverflowTable).offset;
                length = bytecodeFile.overflowStringTable.get(offsetToOverflowTable).length;
                
            } else {
                offset = bytecodeFile.smallStringTable.get(i).offset;

            }

            int address = bytecodeFile.stringStorage.get(offset).address;

            for (int j = 0; j < length; j++) {
                stringValue.append((char) bytecodeFile.stringStorage.get(j + offset).entry);
            }

            HbcString stringObject = new HbcString(stringValue.toString(), address, length, isUTF16);
            strings.add(stringObject);
        }

        return strings;
    }

    public static void main(String[] args) {
        String filename = "rnswift_main.jsbundle";
        boolean useStdin = false;

        // Simple argument parsing
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--stdin".equals(arg)) {
                useStdin = true;
            } else if (arg.startsWith("--")) {
                System.err.println("Unknown option: " + arg);
                printUsage();
                System.exit(2);
                return;
            } else {
                filename = arg;
            }
        }

        try {
            byte[] data;
            if (useStdin) {
                // Read from stdin - for simplicity, we'll just read from the file for now
                // In a real implementation, you'd read from System.in
                System.err.println("Stdin reading not implemented, using file: " + filename);
                data = Files.readAllBytes(Paths.get(filename));
            } else {
                data = Files.readAllBytes(Paths.get(filename));
            }

            HbcBinaryStructs.BytecodeFile bytecodeFile = readHbcFile(data);

            List<HbcString> allStrings = getAllStrings(bytecodeFile);
            bytecodeFile.allStrings = allStrings;

            // Clear large data structures to reduce memory usage
            bytecodeFile.stringStorage = null;
            bytecodeFile.overflowStringTable = null;
            bytecodeFile.smallStringTable = null;
            bytecodeFile.identifierHashes = null;
            bytecodeFile.stringKinds = null;

        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
            System.exit(1);
        } catch (RuntimeException e) {
            System.err.println("Error parsing HBC file: " + e.getMessage());
            System.exit(1);
        }
    }
}
