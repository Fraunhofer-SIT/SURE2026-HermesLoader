package hermesloader.inject;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Injection for newArrayWithBufferInject userop.
 * Attempts to resolve buffer address and produce COPY of constant pointer when cached.
 * Falls back to CALLOTHER with original inputs.
 */
public class InjectPayloadHermesNewArrayWithBuffer extends InjectPayloadCallother {

    private void logDebug(String message) {
        Msg.debug(this, message);
    }

    public InjectPayloadHermesNewArrayWithBuffer(String sourceName) {
        super(sourceName);
    }

    @Override
    public PcodeOp[] getPcode(Program program, InjectContext con) {

        try {
            var memory = program.getMemory();
            var block = memory.getBlock("Array Buffer");
            if (block != null && block.isInitialized() && !con.inputlist.isEmpty()) {
                // bufferIndex assumed to be last input
                Varnode bufferIndexVn = con.inputlist.get(2);
                Varnode numElementsVn = con.inputlist.get(1);
                // Only proceed if bufferIndex is a constant
                if (bufferIndexVn.isConstant()) {
                    long offset = bufferIndexVn.getOffset();
                    long blockSize = block.getSize();
                    if (offset >= 0 && offset < blockSize) {
                        Address elementAddr = block.getStart().add(offset);
                        // If we have an output varnode, emit COPY of pointer (not dereferenced value)
                        if (!con.output.isEmpty()) {
                            if (numElementsVn.isConstant()) {
                                long numElements = numElementsVn.getOffset();
                                
                                // read array type
                                // read array type from memory & parse each element
                                // Header format per HermesArrayBufferParser:
                                // Byte0: bit7=extended(0x80); bits6-4=tag type (mask 0x70); bits3-0=length nibble (or high 4 bits if extended)
                                // Byte1: only meaningful if extended (low 8 bits of 12-bit length)
                                String tagName = "Unknown";
                                long declaredCount = -1;
                                boolean extendedHeader = false;
                                int elemSize = 0;
                                boolean logical = false; // true for Null/True/False (no payload bytes)
                                Address payloadAddr = null;
                                int headerLen = 0;
                                try {
                                    byte first = memory.getByte(elementAddr);
                                    int firstU = first & 0xFF;
                                    extendedHeader = (firstU & 0x80) != 0;
                                    int tagType = firstU & 0x70; // upper nibble masked
                                    if (extendedHeader) {
                                        headerLen = 2;
                                        byte second = memory.getByte(elementAddr.add(1));
                                        int secondU = second & 0xFF;
                                        declaredCount = ((firstU & 0x0F) << 8) | secondU; // 12-bit count
                                    } else {
                                        headerLen = 1;
                                        declaredCount = (firstU & 0x0F);
                                    }
                                    switch (tagType) {
                                        case (0 << 4) -> { tagName = "Null"; logical = true; }
                                        case (1 << 4) -> { tagName = "True"; logical = true; }
                                        case (2 << 4) -> { tagName = "False"; logical = true; }
                                        case (3 << 4) -> { tagName = "Number"; elemSize = 8; }
                                        case (4 << 4) -> { tagName = "LongStringRef"; elemSize = 4; }
                                        case (5 << 4) -> { tagName = "ShortStringRef"; elemSize = 2; }
                                        case (6 << 4) -> { tagName = "ByteStringRef"; elemSize = 1; }
                                        case (7 << 4) -> { tagName = "Integer"; elemSize = 4; }
                                        default -> { tagName = "Unknown(0x" + Integer.toHexString(tagType) + ")"; }
                                    }
                                    payloadAddr = elementAddr.add(headerLen);
                                } catch (MemoryAccessException mae) {
                                    logDebug("Failed to read array header at " + elementAddr + ": " + mae.getMessage());
                                } catch (Exception ex) {
                                    logDebug("Unexpected error decoding header at " + elementAddr + ": " + ex);
                                }


                                if (numElements > 10) {
                                    // Use FlatProgramAPI to set a plate (pre) comment which appears in decompiler.
                                    try {
                                        FlatProgramAPI api = new FlatProgramAPI(program, TaskMonitor.DUMMY);
                                        String newComment = "Array allocation: elements=" + numElements + "; type=" + tagName +
                                                (declaredCount >= 0 ? (" declaredCount=" + declaredCount) : "") +
                                                (extendedHeader ? " (extended)" : "");
                                        // Overwrite or create a pre-comment; duplication avoidance skipped (no non-deprecated getter available here).
                                        api.setPreComment(con.baseAddr, newComment);
                                    } catch (Exception ignore) {
                                        // Non-fatal; continue with pcode emission.
                                        logDebug("Failed to set comment at " + con.baseAddr);
                                    }
                                } else {                                  
                                    // Build CALLOTHER with constant element values instead of a pointer-only fallback.

                                    // Prepare CALLOTHER op that includes parsed constant elements appended after original inputs.
                                    if (declaredCount >= 0 && con.output.size() > 0) {
                                        AddressFactory af = program.getAddressFactory();
                                        int callotherId = InjectPayloadHermesGetById.getUserOpIdByName(program, "newArrayWithBuffer");
                                        PcodeOp op = new PcodeOp(con.baseAddr, 0, PcodeOp.CALLOTHER);
                                        Varnode idVn = new Varnode(af.getConstantAddress(callotherId), 1);
                                        op.setInput(idVn, 0);
                                        // Original inputs first (sizeHint, numElements, bufferIndex)—maintain ordering
                                        int inputSlot = 1;
                                        for (int i = 0; i < con.inputlist.size(); i++) {
                                            op.setInput(con.inputlist.get(i), inputSlot++);
                                        }

                                        // override buffer index with absolute buffer location
                                        int ptrSize = con.output.get(0).getSize();
                                        Varnode constPtr = new Varnode(af.getConstantAddress(elementAddr.getOffset()), ptrSize);
                                        op.setInput(constPtr, 3);

                                        long elementCount = declaredCount;
                                        // Cap to small array numElements if mismatch; prefer declaredCount but avoid huge expansions.
                                        if (elementCount > numElements) {
                                            elementCount = numElements; // assume allocation matches header for injection context
                                        }
                                        // We will only append up to a safety cap (e.g., 64) though branch ensures numElements <= 10.
                                        long cap = Math.min(elementCount, 64);
                                        if (logical) {
                                            // Represent logical values as 1-byte constants: Null=0, True=1, False=2
                                            int logicalVal = switch (tagName) {
                                                case "Null" -> 0;
                                                case "True" -> 1;
                                                case "False" -> 2;
                                                default -> 0xFF; // Unknown logical sentinel
                                            };
                                            for (int i = 0; i < cap; i++) {
                                                Varnode logicalConst = new Varnode(af.getConstantAddress(logicalVal), 1);
                                                op.setInput(logicalConst, inputSlot++);
                                            }
                                        } else if (elemSize > 0 && payloadAddr != null) {
                                            long totalBytesNeeded = elementCount * (long)elemSize;
                                            long blockRemaining = block.getSize() - offset - headerLen;
                                            boolean truncated = totalBytesNeeded > blockRemaining;
                                            long actualElements = truncated ? (blockRemaining / elemSize) : elementCount;
                                            cap = Math.min(actualElements, cap);
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
                                                        int ptrSizeElem = con.output.get(0).getSize();
                                                        Varnode stringPtrVn = new Varnode(strEntryAddr, ptrSizeElem);
                                                        op.setInput(stringPtrVn, inputSlot++);
                                                    } else {
                                                        // Use constant address space for the numeric value; varnode size = elemSize (at least 1)
                                                        Varnode constElem = new Varnode(af.getConstantAddress(maskedValue), Math.max(1, elemSize));
                                                        op.setInput(constElem, inputSlot++);
                                                    }
                                                } catch (MemoryAccessException mae) {
                                                            logDebug("Failed reading element " + i + " at " + elemAddr + ": " + mae.getMessage());
                                                    break; // stop further attempts
                                                }
                                            }
                                        }

                                        // Set output(s)
                                        for (int i = 0; i < con.output.size(); i++) {
                                            op.setOutput(con.output.get(i));
                                        }
                                        return new PcodeOp[] { op }; // Return enriched CALLOTHER instead of pointer COPY for small arrays
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            logDebug("Exception during fast-path injection: " + e);
            // Swallow and fallback to CALLOTHER
        }

        // Fallback: emit CALLOTHER with all inputs (sizeHint, numElements, bufferIndex)
        PcodeOp op = new PcodeOp(con.baseAddr, 0, PcodeOp.CALLOTHER);
        AddressFactory af = program.getAddressFactory();
        int callotherId = InjectPayloadHermesGetById.getUserOpIdByName(program, "newArrayWithBuffer");
        Varnode idVn = new Varnode(af.getConstantAddress(callotherId), 1);
        op.setInput(idVn, 0);
        for (int i = 0; i < con.inputlist.size(); i++) {
            op.setInput(con.inputlist.get(i), i + 1);
        }
        // set output
        for (int i = 0; i < con.output.size(); i++) {
            op.setOutput(con.output.get(i));
        }
        return new PcodeOp[] { op };
    }
}
