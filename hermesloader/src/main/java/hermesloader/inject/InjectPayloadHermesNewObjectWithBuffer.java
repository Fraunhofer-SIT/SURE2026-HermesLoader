package hermesloader.inject;

import ghidra.program.flatapi.FlatProgramAPI;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import hermesloader.parser.HermesArrayBufferParser;
import hermesloader.structs.HermesArrayBufferDataTypes;

/**
 * Injection for newObjectWithBufferInject userop.
 * Attempts to resolve buffer address and produce COPY of constant pointer when cached.
 * Falls back to CALLOTHER with original inputs.
 *
 * This is adapted from InjectPayloadHermesNewArrayWithBuffer; object buffers currently
 * reuse the same heuristic: if the buffer index is constant and within the "Array Buffer" block
 * we emit either an enriched CALLOTHER (for small element/property count) or a pointer COPY.
 * If later an "Object Buffer" memory block is introduced, update the block lookup name.
 */
public class InjectPayloadHermesNewObjectWithBuffer extends InjectPayloadCallother {

    private void logDebug(String message) {
        Msg.debug(this, message);
    }

    public InjectPayloadHermesNewObjectWithBuffer(String sourceName) {
        super(sourceName);
    }

    /**
     * Resolve entry address for a key/value element. For StringRef tags we convert the raw
     * index into the loaded string table base (0xA0000000 + index*9). For other tags we use
     * the element's memory location itself. Logical tags (Null/True/False) produce synthetic
     * 1-byte values but still return the element address.
     */
    private List<Address> resolveEntryAddress(Program program, Memory memory, Address elementAddr, Address callerAddr) {

        // Parse header similar to array approach
        FlatProgramAPI api = new FlatProgramAPI(program, TaskMonitor.DUMMY);
        final StructureDataType extendedHeaderDt = HermesArrayBufferDataTypes.createSegmentHeader();
        List<Address> results = new ArrayList<>();
        AddressFactory af = program.getAddressFactory();
        results.add(af.getConstantAddress(elementAddr.getOffset()));
        long declaredCount = -1;
        boolean extendedHeader = false;
        Address payloadAddr = null;
        int headerLen = 0;
        String tagName = "Unknown";
        int elemSize = 0;
        boolean logical = false;
        DataType elemType = null;
        try {
            byte first = memory.getByte(elementAddr);
            int firstU = first & 0xFF;
            extendedHeader = (firstU & 0x80) != 0;
            int tagType = firstU & 0x70;
            if (extendedHeader) {
                headerLen = 2;
                byte second = memory.getByte(elementAddr.add(1));
                int secondU = second & 0xFF;
                declaredCount = ((firstU & 0x0F) << 8) | secondU;
                // Only create header structure if undefined
                if (program.getListing().getDataAt(elementAddr) != null && DataUtilities.isUndefinedData(program, elementAddr)) {
                    DataUtilities.createData(api.getCurrentProgram(), elementAddr, extendedHeaderDt, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                }
            } else {
                headerLen = 1;
                declaredCount = (firstU & 0x0F);
                if (program.getListing().getDataAt(elementAddr) != null && DataUtilities.isUndefinedData(program, elementAddr)) {
                    DataUtilities.createData(api.getCurrentProgram(), elementAddr, ByteDataType.dataType, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                }
            }
            
            switch (tagType) {
                case (0 << 4) -> { tagName = "Null"; logical = true; elemType = null; }
                case (1 << 4) -> { tagName = "True"; logical = true; elemType = null; }
                case (2 << 4) -> { tagName = "False"; logical = true; elemType = null; }
                case (3 << 4) -> { tagName = "Number"; elemSize = 8; elemType = HermesArrayBufferDataTypes.numberValueType();}
                case (4 << 4) -> { tagName = "LongStringRef"; elemSize = 4;  elemType = HermesArrayBufferDataTypes.longStringRefType(); }
                case (5 << 4) -> { tagName = "ShortStringRef"; elemSize = 2; elemType = HermesArrayBufferDataTypes.shortStringRefType(); }
                case (6 << 4) -> { tagName = "ByteStringRef"; elemSize = 1; elemType = HermesArrayBufferDataTypes.byteStringRefType(); }
                case (7 << 4) -> { tagName = "Integer"; elemSize = 4; elemType = HermesArrayBufferDataTypes.integerValueType(); }
                default -> tagName = "Unknown(0x" + Integer.toHexString(tagType) + ")";
            }
            payloadAddr = elementAddr.add(headerLen);
        } catch (MemoryAccessException mae) {
            Msg.debug(this, "Failed to read object header at " + elementAddr + ": " + mae.getMessage());
        } catch (Exception ex) {
            Msg.debug(this, "Unexpected error decoding header at " + elementAddr + ": " + ex);
        }

        api.setPreComment(elementAddr, String.format("ArrayBuffer Segment Header: tag=%s count=%d", tagName, declaredCount));

        long cap = Math.min(declaredCount, 64);

        if (logical) {
            // Represent logical values as 1-byte constants: Null=0, True=1, False=2
            int logicalVal = switch (tagName) {
                case "Null" -> 0;
                case "True" -> 1;
                case "False" -> 2;
                default -> 0xFF; // Unknown logical sentinel
            };
            for (int i = 0; i < cap; i++) {
                Address logicalConst = af.getConstantAddress(logicalVal);
                results.add(logicalConst);
            }
        } else if (elemSize > 0 && payloadAddr != null) {

            try {
                if (program.getListing().getDataAt(payloadAddr) != null && DataUtilities.isUndefinedData(program, payloadAddr)) {
                    ArrayDataType arrDt = new ArrayDataType(elemType, (int)declaredCount, elemSize);
                    DataUtilities.createData(api.getCurrentProgram(), payloadAddr, arrDt, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
                }
            } catch (CodeUnitInsertionException t) {
                Msg.debug(HermesArrayBufferParser.class, "Failed to create element array at " + payloadAddr + ": " + t.getMessage());
            }

            for (int i = 0; i < cap; i++) {
                Address elemAddr = payloadAddr.add((long)i * elemSize);
                try {
                    long value = 0;
                    for (int b = 0; b < elemSize; b++) {
                        int byteVal = memory.getByte(elemAddr.add(b)) & 0xFF;
                        value |= ((long)byteVal) << (8 * b);
                    }
                    // Normalize value sizes to 8-byte constant container but truncated to element size semantics.
                    long maskedValue = switch (elemSize) {
                        case 8 -> value;
                        case 4 -> (value & 0xFFFFFFFFL);
                        case 2 -> (value & 0xFFFFL);
                        case 1 -> (value & 0xFFL);
                        default -> value; // unexpected size
                    };
                    // If this is a StringRef array, inject pointer into Loaded String Table (base 0xA0000000 + index*9)
                    boolean isStringRef = "LongStringRef".equals(tagName) || "ShortStringRef".equals(tagName) || "ByteStringRef".equals(tagName);
                    if (isStringRef) {
                        long stringIndex = switch (tagName) {
                            case "LongStringRef" -> maskedValue & 0xFFFFFFFFL;
                            case "ShortStringRef" -> maskedValue & 0xFFFFL;
                            case "ByteStringRef" -> maskedValue & 0xFFL;
                            default -> maskedValue; // unreachable
                        };
                        // Compute loaded string table entry address: entry size = 9 bytes.
                        long entryAddrOff = 0xA0000000L + (stringIndex * 9L);
                        Address strEntryAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entryAddrOff);
                        results.add(strEntryAddr);

                        // add xref
                        try {
                            program.getReferenceManager().addMemoryReference(callerAddr, strEntryAddr, RefType.READ, SourceType.ANALYSIS, i);
                        } catch (Exception ignoredRef) {
                            logDebug("Failed adding string reference at " + callerAddr + " -> " + strEntryAddr + ": " + ignoredRef.getMessage());
                        }
                    } else {
                        // Use constant address space for the numeric value
                        Address constElem = af.getConstantAddress(maskedValue);
                        results.add(constElem);
                    }
                } catch (MemoryAccessException mae) {
                    Msg.debug(this, "Failed reading element " + i + " at " + elemAddr + ": " + mae.getMessage());
                    break; // stop further attempts
                }
            }
        }

        return results;
    }

    @Override
    public PcodeOp[] getPcode(Program program, InjectContext con) {
        Address keyAddr = null;
        Address valueAddr = null;
        try {
            var memory = program.getMemory();
            var blockKeys = memory.getBlock("Object Key Buffer");
            var blockValues = memory.getBlock("Object Value Buffer");
            if (blockKeys != null && blockKeys.isInitialized() && blockValues != null && blockValues.isInitialized() && !con.inputlist.isEmpty() && con.inputlist.size() >= 4) {
                Varnode bufferKeyVn = con.inputlist.get(2);
                Varnode bufferValueVn = con.inputlist.get(3);
                Varnode propertyCountVn = con.inputlist.get(1);
                if (bufferKeyVn.isConstant() && bufferValueVn.isConstant()) {
                    long keyOffset = bufferKeyVn.getOffset();
                    long blockKeysSize = blockKeys.getSize();

                    long valueOffset = bufferValueVn.getOffset();
                    long blockValuesSize = blockValues.getSize();
                    if (keyOffset >= 0 && keyOffset < blockKeysSize) {
                        keyAddr = blockKeys.getStart().add(keyOffset);

                        if (valueOffset >= 0 && valueOffset < blockValuesSize) {
                            valueAddr = blockValues.getStart().add(valueOffset);

                            if (!con.output.isEmpty()) {
                                if (propertyCountVn.isConstant()) {
                                    long propertyCount = propertyCountVn.getOffset();

                                    // create datalayout in Object Key/Value Buffers


                                    if (propertyCount > 10) {
                                        // Large object: annotate only
                                        try {
                                            FlatProgramAPI api = new FlatProgramAPI(program, TaskMonitor.DUMMY);
                                            api.setPreComment(con.baseAddr, "Object allocation: properties=" + propertyCount);
                                        } catch (Exception ignored) {
                                            logDebug("Failed to set pre-comment at " + con.baseAddr + ": " + ignored.getMessage());
                                        }
                                    } else {

                                        List<Address> keyEntryAddrs = resolveEntryAddress(program, memory, keyAddr, con.baseAddr);
                                        List<Address> valueEntryAddrs = resolveEntryAddress(program, memory, valueAddr, con.baseAddr);
                                        // Split into two CALLOTHER ops: first carries keys, second carries values.
                                        AddressFactory af = program.getAddressFactory();
                                        int callotherId = InjectPayloadHermesGetById.getUserOpIdByName(program, "newObjectWithBuffer");

                                        // Prepare key op
                                        PcodeOp keyOp = new PcodeOp(con.baseAddr, 0, PcodeOp.CALLOTHER);
                                        Varnode idVnKey = new Varnode(af.getConstantAddress(callotherId), 1);
                                        keyOp.setInput(idVnKey, 0);
                                        int keySlot = 1;
                                        keyOp.setInput(con.inputlist.get(0), keySlot++); // size hint
                                        keyOp.setInput(con.inputlist.get(1), keySlot++); // property count
                                        int ptrSize = con.output.get(0).getSize();
                                        for (Address a : keyEntryAddrs) {
                                            keyOp.setInput(new Varnode(a, ptrSize), keySlot++);
                                        }
                                        // No outputs on keyOp (annotation only)

                                        // Prepare value op
                                        PcodeOp valueOp = new PcodeOp(con.baseAddr, 0, PcodeOp.CALLOTHER);
                                        Varnode idVnVal = new Varnode(af.getConstantAddress(callotherId), 1);
                                        valueOp.setInput(idVnVal, 0);
                                        int valSlot = 1;
                                        valueOp.setInput(con.inputlist.get(0), valSlot++); // size hint
                                        valueOp.setInput(con.inputlist.get(1), valSlot++); // property count
                                        for (Address a : valueEntryAddrs) {
                                            valueOp.setInput(new Varnode(a, ptrSize), valSlot++);
                                        }
                                        // Preserve original outputs on value op
                                        for (int i = 0; i < con.output.size(); i++) {
                                            valueOp.setOutput(con.output.get(i));
                                        }

                                        // Add descriptive comments
                                        try {
                                            FlatProgramAPI api = new FlatProgramAPI(program, TaskMonitor.DUMMY);
                                            api.setPreComment(con.baseAddr, "newObjectWithBuffer 1: (keys); newObjectWithBuffer 2: (values)");
                                        } catch (Exception ignored) {
                                            logDebug("Failed to set split-call comment at " + con.baseAddr + ": " + ignored.getMessage());
                                        }

                                        return new PcodeOp[] { keyOp, valueOp };
                                        
                                    }
                                }
                            }

                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Exception during fast-path injection: " + e);
        }
        // Fallback CALLOTHER
        PcodeOp op = new PcodeOp(con.baseAddr, 0, PcodeOp.CALLOTHER);
        AddressFactory af = program.getAddressFactory();
        int callotherId = InjectPayloadHermesGetById.getUserOpIdByName(program, "newObjectWithBuffer");
        Varnode idVn = new Varnode(af.getConstantAddress(callotherId), 1);
        op.setInput(idVn, 0);
        int inputSlot = 1;

        // set size hint
        op.setInput(con.inputlist.get(0), inputSlot);
        inputSlot++;
        // set property count
        op.setInput(con.inputlist.get(1), inputSlot);
        inputSlot++;
        // set key pointer
        if (keyAddr != null) {
            Varnode keyPtr = new Varnode(af.getConstantAddress(keyAddr.getOffset()), con.inputlist.get(2).getSize());
            op.setInput(keyPtr, inputSlot);
        } else {
            op.setInput(con.inputlist.get(2), inputSlot);
        }
        inputSlot++;
        // set value pointer
        if (valueAddr != null) {
            Varnode valPtr = new Varnode(af.getConstantAddress(valueAddr.getOffset()), con.inputlist.get(3).getSize());
            op.setInput(valPtr, inputSlot);
        } else {
            op.setInput(con.inputlist.get(3), inputSlot);
        }
        inputSlot++;

        for (int i = 0; i < con.output.size(); i++) {
            op.setOutput(con.output.get(i));
        }
        return new PcodeOp[] { op };
    }
}
