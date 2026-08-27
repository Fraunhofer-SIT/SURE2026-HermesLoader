package hermesloader.parser;

import java.util.List;

public class HbcBinaryStructs {
    private static final long MAGIC = 0x1F1903C103BC1FC6L;

    public static class BytecodeOptions {
        public int staticBuiltins;
        public int cjsModulesStaticallyResolved;
        public int hasAsync;
        public int flags;

        public BytecodeOptions(BitBufferReader reader) {
            this.staticBuiltins = reader.readBits(1);
            this.cjsModulesStaticallyResolved = reader.readBits(1);
            this.hasAsync = reader.readBits(1);
            this.flags = reader.readBits(1);
            reader.readBits(4); // Skip 4 bit padding
        }

        @Override
        public String toString() {
            return String.format("BytecodeOptions(staticBuiltins=%d, cjsModulesStaticallyResolved=%d, hasAsync=%d, flags=%d)",
                    staticBuiltins, cjsModulesStaticallyResolved, hasAsync, flags);
        }
    }

    public static class FuncHeader extends FunctionInfoBase {

        public FuncHeader(BitBufferReader reader) {
            this.offset = reader.readUInt32();
            this.paramCount = reader.readUInt32();
            this.bytecodeSizeInBytes = reader.readUInt32();
            this.functionName = reader.readUInt32();
            this.infoOffset = reader.readUInt32();
            this.frameSize = reader.readUInt32();
            this.environmentSize = reader.readUInt32();
            this.highestReadCacheIndex = reader.readByte();
            this.highestWriteCacheIndex = reader.readByte();
            this.flags = reader.readByte();
        }

        @Override
        public String toString() {
            return String.format("FuncHeader(offset=%d, paramCount=%d, bytecodeSizeInBytes=%d, functionName=%d, infoOffset=%d, frameSize=%d, environmentSize=%d, highestReadCacheIndex=%d, highestWriteCacheIndex=%d, flags=%d)",
                    offset, paramCount, bytecodeSizeInBytes, functionName, infoOffset, frameSize, environmentSize, highestReadCacheIndex, highestWriteCacheIndex, flags);
        }
    }

    public static class SmallFuncHeader extends FunctionInfoBase {

        public SmallFuncHeader(BitBufferReader reader) {
            this.offset = reader.readBits(25);
            this.paramCount = reader.readBits(7);
            this.bytecodeSizeInBytes = reader.readBits(15);
            this.functionName = reader.readBits(17);
            this.infoOffset = reader.readBits(25);
            this.frameSize = reader.readBits(7);
            this.environmentSize = reader.readBits(8);
            this.highestReadCacheIndex = reader.readBits(8);
            this.highestWriteCacheIndex = reader.readBits(8);
            this.flags = reader.readBits(8);
        }

        @Override
        public String toString() {
            return String.format("SmallFuncHeader(offset=%d, paramCount=%d, bytecodeSizeInBytes=%d, functionName=%d, infoOffset=%d, frameSize=%d, environmentSize=%d, highestReadCacheIndex=%d, highestWriteCacheIndex=%d, flags=%d)",
                    offset, paramCount, bytecodeSizeInBytes, functionName, infoOffset, frameSize, environmentSize, highestReadCacheIndex, highestWriteCacheIndex, flags);
        }
    }

    public static class BytecodeFileHeader {
        public long magic;
        public int version;
        public int[] sourceHash;
        public int fileLength;
        public int globalCodeIndex;
        public int functionCount;
        public int stringKindCount;
        public int identifierCount;
        public int stringCount;
        public int overflowStringCount;
        public int stringStorageSize;
        public int bigIntCount;
        public int bigIntStorageSize;
        public int regExpCount;
        public int regExpStorageSize;
        public int arrayBufferSize;
        public int objKeyBufferSize;
        public int objValueBufferSize;
        public int segmentID;
        public int cjsModuleCount;
        public int functionSourceCount;
        public int debugInfoOffset;
        public BytecodeOptions options;

        public BytecodeFileHeader(BitBufferReader reader) {
            this.magic = reader.readUInt64();

            if (this.magic != MAGIC) {
                throw new RuntimeException(
                    String.format("Not a Hermes .hbc file (magic=%016X, expected %016X)",
                        this.magic, MAGIC)
                );
            }

            this.version = reader.readUInt32();
            this.sourceHash = new int[20];
            for (int i = 0; i < 20; i++) {
                this.sourceHash[i] = reader.readByte();
            }
            this.fileLength = reader.readUInt32();
            this.globalCodeIndex = reader.readUInt32();
            this.functionCount = reader.readUInt32();
            this.stringKindCount = reader.readUInt32();
            this.identifierCount = reader.readUInt32();
            this.stringCount = reader.readUInt32();
            this.overflowStringCount = reader.readUInt32();
            this.stringStorageSize = reader.readUInt32();
            this.bigIntCount = reader.readUInt32();
            this.bigIntStorageSize = reader.readUInt32();
            this.regExpCount = reader.readUInt32();
            this.regExpStorageSize = reader.readUInt32();
            this.arrayBufferSize = reader.readUInt32();
            this.objKeyBufferSize = reader.readUInt32();
            this.objValueBufferSize = reader.readUInt32();
            this.segmentID = reader.readUInt32();
            this.cjsModuleCount = reader.readUInt32();
            this.functionSourceCount = reader.readUInt32();
            this.debugInfoOffset = reader.readUInt32();
            this.options = new BytecodeOptions(reader);
            reader.readBytes(19); // Skip padding bits
        }

        @Override
        public String toString() {
            return String.format("BytecodeFileHeader(magic=%016X, version=%d, sourceHash=%s, fileLength=%d, globalCodeIndex=%d, functionCount=%d, stringKindCount=%d, identifierCount=%d, stringCount=%d, overflowStringCount=%d, stringStorageSize=%d, bigIntCount=%d, bigIntStorageSize=%d, regExpCount=%d, regExpStorageSize=%d, arrayBufferSize=%d, objKeyBufferSize=%d, objValueBufferSize=%d, segmentID=%d, cjsModuleCount=%d, functionSourceCount=%d, debugInfoOffset=%d, options=%s)",
                    magic, version, java.util.Arrays.toString(sourceHash), fileLength, globalCodeIndex, functionCount, stringKindCount, identifierCount, stringCount, overflowStringCount, stringStorageSize, bigIntCount, bigIntStorageSize, regExpCount, regExpStorageSize, arrayBufferSize, objKeyBufferSize, objValueBufferSize, segmentID, cjsModuleCount, functionSourceCount, debugInfoOffset, options);
        }
    }

    public static class DebugInfoHeader {
        public int filenameCount;
        public int filenameStorageSize;
        public int fileRegionCount;
        public int scopeDescDataOffset;
        public int textifiedCalleeOffset;
        public int stringTableOffset;
        public int debugDataSize;

        public DebugInfoHeader(BitBufferReader reader) {
            this.filenameCount = reader.readUInt32();
            this.filenameStorageSize = reader.readUInt32();
            this.fileRegionCount = reader.readUInt32();
            this.scopeDescDataOffset = reader.readUInt32();
            this.textifiedCalleeOffset = reader.readUInt32();
            this.stringTableOffset = reader.readUInt32();
            this.debugDataSize = reader.readUInt32();
        }

        @Override
        public String toString() {
            return String.format("DebugInfoHeader(filenameCount=%d, filenameStorageSize=%d, fileRegionCount=%d, scopeDescDataOffset=%d, textifiedCalleeOffset=%d, stringTableOffset=%d, debugDataSize=%d)",
                    filenameCount, filenameStorageSize, fileRegionCount, scopeDescDataOffset, textifiedCalleeOffset, stringTableOffset, debugDataSize);
        }
    }

    public static class SmallStringTableEntry {
        public boolean isUTF16;
        public int offset;
        public int length;

        public SmallStringTableEntry(BitBufferReader reader) {
            this.isUTF16 = reader.readBits(1) != 0;
            this.offset = reader.readBits(23);
            this.length = reader.readBits(8);
        }

        @Override
        public String toString() {
            return String.format("SmallStringTableEntry(isUTF16=%b, offset=%d, length=%d)",
                    isUTF16, offset, length);
        }
    }

    public static class OverflowStringTableEntry {
        public int offset;
        public int length;

        public OverflowStringTableEntry(BitBufferReader reader) {
            this.offset = reader.readUInt32();
            this.length = reader.readUInt32();
        }

        @Override
        public String toString() {
            return String.format("OverflowStringTableEntry(offset=%d, length=%d)",
                    offset, length);
        }
    }

    public static class HbcString {
        public String value;
        public int address;
        public int length;
        public boolean isUTF16;

        public HbcString(String value, int address, int length, boolean isUTF16) {
            this.value = value;
            this.address = address;
            this.length = length;
            this.isUTF16 = isUTF16;
        }

        @Override
        public String toString() {
            return String.format("HbcString(value=%s, address=%d, length=%d, isUTF16=%b)",
                    value, address, length, isUTF16);
        }
    }

    public static class StringStorageEntry {
        public int address;
        public int entry;

        public StringStorageEntry(BitBufferReader reader) {
            this.address = reader.getBytePos();
            this.entry = reader.readBits(8);
        }

        @Override
        public String toString() {
            return String.format("StringStorageEntry(entry=%d, address=%d)",
                    entry, address);
        }
    }

    public static class StringKind {
        public int kind;

        public StringKind(BitBufferReader reader) {
            this.kind = reader.readUInt32();
        }

        @Override
        public String toString() {
            return String.format("StringKind(kind=%d)", kind);
        }
    }

    public static class IdentifierHash {
        public int hash;

        public IdentifierHash(BitBufferReader reader) {
            this.hash = reader.readUInt32();
        }

        @Override
        public String toString() {
            return String.format("IdentifierHash(hash=%d)", hash);
        }
    }

    public static class BytecodeFile {
        public BytecodeFileHeader bytecodeFileHeader;
        public List<FunctionInfo> functions;
        public DebugInfoHeader debugInfoHeader;
        public List<StringKind> stringKinds;
        public List<IdentifierHash> identifierHashes;
        public List<SmallStringTableEntry> smallStringTable;
        public List<OverflowStringTableEntry> overflowStringTable;
        public List<StringStorageEntry> stringStorage;
        public List<HbcString> allStrings;

        public BytecodeFile(BytecodeFileHeader bytecodeFileHeader,
                          List<FunctionInfo> functions,
                          DebugInfoHeader debugInfoHeader,
                          List<StringKind> stringKinds,
                          List<IdentifierHash> identifierHashes,
                          List<SmallStringTableEntry> smallStringTable,
                          List<OverflowStringTableEntry> overflowStringTable,
                          List<StringStorageEntry> stringStorage) {
            this.bytecodeFileHeader = bytecodeFileHeader;
            this.functions = functions;
            this.debugInfoHeader = debugInfoHeader;
            this.stringKinds = stringKinds;
            this.identifierHashes = identifierHashes;
            this.smallStringTable = smallStringTable;
            this.overflowStringTable = overflowStringTable;
            this.stringStorage = stringStorage;
        }
    }

    public static abstract class FunctionInfoBase {
        public int offset;
        public int paramCount;
        public int bytecodeSizeInBytes;
        public int functionName;
        public int infoOffset;
        public int frameSize;
        public int environmentSize;
        public int highestReadCacheIndex;
        public int highestWriteCacheIndex;
        public int flags;

    }

    public static class FunctionInfo {
        public SmallFuncHeader smallFuncHeader;
        public FuncHeader funcHeader;

        public FunctionInfo(SmallFuncHeader smallFuncHeader, FuncHeader funcHeader) {
            this.smallFuncHeader = smallFuncHeader;
            this.funcHeader = funcHeader;
        }
    }
}
