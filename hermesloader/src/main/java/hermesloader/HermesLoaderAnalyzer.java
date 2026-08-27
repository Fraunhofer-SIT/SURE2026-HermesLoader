/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package hermesloader;

import java.io.ByteArrayInputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import generic.concurrent.QCallback;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction; // needed for iterator generic
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Hermes analyzer that resolves indirect call targets (especially getById chains),
 * derives closure/function reference statistics, and creates synthetic helper stubs
 * for global register based dispatch targets.
 */
public class HermesLoaderAnalyzer extends AbstractAnalyzer {

	private static final String LOG_PREFIX = "[HermesLoaderAnalyzer] ";
	public static final Map<String, Address> fieldAddressPutCache =
		Collections.synchronizedMap(new HashMap<>());
	public static final Map<Address, Address> globalFieldAddressCache =
		Collections.synchronizedMap(new HashMap<>());
	/** Lock object to guard creation of synthetic global helper functions. */
	private static final Object GLOBAL_FUNCTION_CREATE_LOCK = new Object();

	private static void logInfo(String message) {
		Msg.info(HermesLoaderAnalyzer.class, LOG_PREFIX + message);
	}

	private static void logWarn(String message) {
		Msg.warn(HermesLoaderAnalyzer.class, LOG_PREFIX + message);
	}


	/**
	 * Helper class to hold results of getById analysis (string and opcode).
	 */
	private static class GetByIdResult {
		public String fieldName;
		public PcodeOp pcodeOp;
		public String objectString;
		public GetByIdResult() {}
	}

	// Option keys
	private static final String OPTION_ENABLE_FUNCTION_CLOSURE = "Enable Function Closure Analysis";
	private static final String OPTION_ENABLE_INDIRECT_CALL = "Enable Indirect Call Analysis";
	private static final String OPTION_ENABLE_PRINT_STATS = "Enable Print Stats";

	// Option values
	private boolean enableFunctionClosure;
	private boolean enableIndirectCall;
	private boolean printStats;
    
	public HermesLoaderAnalyzer() {
		// Provide a descriptive name & description so users understand purpose in Analysis Options
		super("Hermes Function Reference Summary",
			"Counts functions that are actually referenced (called) and validates call targets.",
			AnalyzerType.INSTRUCTION_ANALYZER);
		AnalysisPriority analysisPriority = AnalysisPriority.DATA_TYPE_PROPOGATION.after();
        setPriority(analysisPriority);
	}

	// Helper synthetic block parameters for creating stub functions
	private static final String HELPER_BLOCK_NAME = "HelperFunctions";
	private static final long HELPER_BASE = 0xf1000000L; // base address for helper functions
	private static final long HELPER_SIZE = 0x00100000L; // 1 MB region for stubs

	/** Ensure a synthetic memory block exists for helper (stub) functions. */
	private void ensureHelperBlock(Program program) {
		AddressSpace ram = program.getAddressFactory().getAddressSpace("ram");
		if (ram == null) {
			logWarn("Cannot create helper block: missing ram address space");
			return;
		}
		Address start = ram.getAddress(HELPER_BASE);
		Memory mem = program.getMemory();
		MemoryBlock existing = mem.getBlock(HELPER_BLOCK_NAME);
		if (existing != null) {
			return;
		}
		try {
			byte[] zeros = new byte[(int) HELPER_SIZE];
			MemoryBlock block = mem.createInitializedBlock(HELPER_BLOCK_NAME, start,
				new ByteArrayInputStream(zeros), HELPER_SIZE, TaskMonitor.DUMMY, false);
			block.setExecute(true);
			block.setWrite(true);
			block.setRead(true);
			logInfo("Created helper block at " + start + " size=" + HELPER_SIZE);
		} catch (Exception e) {
			logWarn("Failed to create helper block: " + e.getClass().getSimpleName() + ": " +
				e.getMessage());
		}
	}

	/**
	 * Recursively follow CAST, INDIRECT, COPY (and chains thereof) to find an originating CALLOTHER.
	 * Stops when a CALLOTHER is found or a non-pass-through op encountered.
	 */
	private PcodeOp traceCallOther(Varnode vn) {
		return traceCallOther(vn, new HashSet<>());
	}

	private PcodeOp traceCallOther(Varnode vn, Set<Varnode> visited) {
		if (vn == null) return null;
		if (!visited.add(vn)) return null; // prevent cycles
		PcodeOp def = vn.getDef();
		if (def == null) return null;
		int op = def.getOpcode();
		if (op == PcodeOp.CALLOTHER) {
			return def;
		}
		if (op == PcodeOp.CAST || op == PcodeOp.INDIRECT || op == PcodeOp.COPY) {
			// follow first input
			if (def.getNumInputs() > 0) {
				return traceCallOther(def.getInput(0), visited);
			}
		}
		return null; // give up on other producers
	}

	private PcodeOp traceOpcode(Varnode vn) {
		return traceOpcode(vn, new HashSet<>());
	}

	private PcodeOp traceOpcode(Varnode vn, Set<Varnode> visited) {
		if (vn == null) return null;
		if (!visited.add(vn)) return null; // prevent cycles
		PcodeOp def = vn.getDef();
		if (def == null) return null;
		int op = def.getOpcode();
		if (op == PcodeOp.CAST || op == PcodeOp.INDIRECT || op == PcodeOp.COPY) {
			// follow first input
			if (def.getNumInputs() > 0) {
				PcodeOp recursiveDef = def.getInput(0).getDef();
				if (recursiveDef == null) return def;
				return traceOpcode(def.getInput(0), visited);
			}
		}
		if (op == PcodeOp.MULTIEQUAL) {
			if (def.getNumInputs() == 2 && !def.getInput(0).toString().equals(def.getInput(1).toString())) {
				if (def.getInput(0).toString().equals(def.getOutput().toString())) {
					PcodeOp recursiveDef = def.getInput(1).getDef();
					if (recursiveDef == null) return def;
					return traceOpcode(def.getInput(1), visited);
				} else if (def.getInput(1).toString().equals(def.getOutput().toString())) {
					PcodeOp recursiveDef = def.getInput(0).getDef();
					if (recursiveDef == null) return def;
					return traceOpcode(def.getInput(0), visited);
				}
			}
		}
		return def;
	}

	public static Address resolveVarnodeAddress(Program program, Varnode vn) {
		if (vn == null) return null;
		if (vn.isAddress()) {
			return vn.getAddress();
		}
		if (vn.isConstant()) {
			// Try RAM space first if it exists, else default space
			AddressSpace space = program.getAddressFactory().getAddressSpace("ram");
			if (space == null) {
				space = program.getAddressFactory().getDefaultAddressSpace();
			}
			return space.getAddress(vn.getOffset());
		}
		// If it's a register holding an address, attempt one-hop trace
		PcodeOp def = vn.getDef();
		if (def != null && def.getOpcode() == PcodeOp.COPY && def.getNumInputs() > 0) {
			return resolveVarnodeAddress(program, def.getInput(0));
		}
		return null;
	}

	public static Address readPointer(Program program, Address addr) {
		Memory mem = program.getMemory();
		if (!mem.contains(addr)) return null;
		int ptrSize = program.getDefaultPointerSize();
		byte[] bytes = new byte[ptrSize];
		try {
			mem.getBytes(addr, bytes);
		} catch (MemoryAccessException e) {
			logWarn("[ptr] read error @" + addr + ": " + e.getMessage());
			return null;
		}
		long value = 0;
		for (int i = 0; i < ptrSize; i++) {
			value |= ((long)(bytes[i] & 0xff)) << (i * 8);
		}
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(value);
	}

	/** Read a null-terminated ASCII string up to maxLen bytes. */
	public static String readCString(Program program, Address addr, int maxLen) {
		if (addr == null) return null;
		Memory mem = program.getMemory();
		if (!mem.contains(addr)) return null;
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < maxLen; i++) {
			Address cur = addr.add(i);
			if (!mem.contains(cur)) break;
			byte[] b = new byte[1];
			try {
				mem.getBytes(cur, b);
			} catch (MemoryAccessException e) {
				logWarn("[str] read error @" + cur + ": " + e.getMessage());
				break;
			}
			int v = b[0] & 0xff;
			if (v == 0) break;
			if (v >= 0x20 && v < 0x7f) sb.append((char)v); else sb.append('.');
		}
		return sb.toString();
	}

	private String callotherToString(PcodeOp op, Program program) {
		int idx = op.getNumInputs() > 0 && op.getInput(0).isConstant() ? (int) op.getInput(0).getOffset() : -1;
		String opString = idx >= 0 ? program.getLanguage().getUserDefinedOpName(idx) : "<unknown>";
		return opString;
	}

	private GetByIdResult analyzeGetById(PcodeOp getByIdOp, Program program) {
		GetByIdResult result = new GetByIdResult();
		Varnode opcodeVn = getByIdOp.getInput(1);
		boolean resolvedGlobalRegister = false;

		// check if getInput(1) is register global 0xC0010
		if (opcodeVn.isRegister()) {
			String regName = opcodeVn.getAddress().toString();
			if (regName.equalsIgnoreCase("register:000c0010")) {
				// special case: hardcoded global register for opcode
				result.objectString = "<global_register>";
				resolvedGlobalRegister = true;
			}
		} else if (opcodeVn.isAddress()) {
			Address addr = opcodeVn.getAddress();
			result.objectString = addr.toString();
		} else if (opcodeVn.isConstant()) {
			result.objectString = Long.toString(opcodeVn.getOffset());
		}

		PcodeOp opcodeDef = traceOpcode(opcodeVn);

		if (opcodeDef != null && opcodeDef.getNumInputs() > 0) {

			if (opcodeDef.getOpcode() == PcodeOp.MULTIEQUAL) {
				if (opcodeDef.getNumInputs() == 2 && !opcodeDef.getInput(0).toString().equals(opcodeDef.getInput(1).toString())) {
					if (opcodeDef.getInput(0).toString().equals(opcodeDef.getOutput().toString())) {
						if (opcodeDef.getInput(1).isRegister()) {
							String regName = opcodeDef.getInput(1).getAddress().toString();
							if (regName.equalsIgnoreCase("register:000c0010")) {
								result.objectString = "<global_register>";
								resolvedGlobalRegister = true;
							}
						}
					} else if (opcodeDef.getInput(1).toString().equals(opcodeDef.getOutput().toString())) {
						if (opcodeDef.getInput(0).isRegister()) {
							String regName = opcodeDef.getInput(0).getAddress().toString();
							if (regName.equalsIgnoreCase("register:000c0010")) {
								result.objectString = "<global_register>";
								resolvedGlobalRegister = true;
							}
						}
					}
				}
			}

			opcodeVn = opcodeDef.getInput(0);

			// check if getInput(1) is register global 0xC0010
			if (opcodeVn.isRegister()) {
				String regName = opcodeVn.getAddress().toString();
				if (regName.equalsIgnoreCase("register:000c0010")) {
					// special case: hardcoded global register for opcode
					result.objectString = "<global_register>";
					resolvedGlobalRegister = true;
				}
			}
		}

		if (!resolvedGlobalRegister) {
			result.pcodeOp = opcodeDef;
		}

		Varnode strPtrVn = getByIdOp.getInput(2);
		Address strPtrAddr = resolveVarnodeAddress(program, strPtrVn);
		if (strPtrAddr != null) {
			String s = readCString(program, strPtrAddr, 256);
			result.fieldName = s != null ? s : "<unresolved>";
		} else {
			result.fieldName = "<unresolved>";
		}
		return result;
	}

	private void createGlobalFunction(String functionName, Address getByIdAddress, Address callAddress, Program program) {
		// Hermes Ret opcode id is 92 decimal (0x5C). Each helper function is a single-byte RET stub.
		final byte HERMES_RET_OPCODE = (byte)0x5C;
		// Guard entire creation sequence to prevent racing threads from creating duplicate stubs
		synchronized (GLOBAL_FUNCTION_CREATE_LOCK) {
			ensureHelperBlock(program); // safe inside lock
			AddressSpace space = program.getAddressFactory().getAddressSpace("ram");
			if (space == null) return;

			// Re-check cache: if we already mapped this getByIdAddress return quickly
			Address existingMapped = globalFieldAddressCache.get(getByIdAddress);
			if (existingMapped != null) {
				// Ensure reference exists (avoid duplicate adds)
				addCallReferenceIfMissing(program, callAddress, existingMapped);
				return;
			}

			Function function = null;
			for (FunctionIterator it = program.getFunctionManager().getFunctions(true); it.hasNext(); ) {
				Function current = it.next();
				if (current.getName().equals(functionName)) {
					function = current;
					break;
				}
			}

			Address functionAddress = null;
			if (function != null) {
				functionAddress = function.getEntryPoint();
			} else {
				// Find first free slot inside helper block
				functionAddress = space.getAddress(HELPER_BASE);
				Address end = space.getAddress(HELPER_BASE + HELPER_SIZE - 1);
				while (functionAddress.compareTo(end) < 0) {
					if (program.getFunctionManager().getFunctionAt(functionAddress) != null) {
						functionAddress = functionAddress.add(0x2); // align by 2 bytes
						continue;
					}
					CreateFunctionCmd cmd = new CreateFunctionCmd(functionName, functionAddress, null, SourceType.USER_DEFINED);
					
					if (!cmd.applyTo(program)) {
						// Another thread may have created it; attempt to locate by name again
						Function created = null;
						for (FunctionIterator it2 = program.getFunctionManager().getFunctions(true); it2.hasNext(); ) {
							Function cur2 = it2.next();
							if (cur2.getName().equals(functionName)) {
								created = cur2; break;
							}
						}
						if (created != null) {
							functionAddress = created.getEntryPoint();
							break; // treat as success
						}
						throw new RuntimeException("Failed to create function " + functionName + " at " + functionAddress + " status=" + cmd.getStatusMsg());
					} else {
						// Initialize one-byte RET stub without reading (uninitialized block read causes exception)
						try {
							Memory mem = program.getMemory();
							if (mem.contains(functionAddress)) {
								mem.setByte(functionAddress, HERMES_RET_OPCODE);
								mem.setByte(functionAddress.add(1), (byte)0x00); // set the argument for return to 0 (reg_0)

								AddressSet rng = new AddressSet();
								rng.addRange(functionAddress, functionAddress.add(1));

								boolean ok = new DisassembleCommand(functionAddress, rng, true).applyTo(program);
								if (!ok) throw new RuntimeException("Disassembly failed");
							}
						} catch (Exception e) {
							throw new RuntimeException("[HermesLoaderAnalyzer] Failed to write RET stub for '" + functionName + "': " + e.getMessage());
						}
					}
					break; // success
				}
			}

			if (functionAddress == null) {
				throw new IllegalStateException("No free helper slot for function " + functionName);
			}

			// Add reference from call site to synthetic global function if absent
			addCallReferenceIfMissing(program, callAddress, functionAddress);
			globalFieldAddressCache.put(getByIdAddress, functionAddress);
		}
	}

	/** Adds a call memory reference if one does not already exist to avoid duplicate refs. */
	private void addCallReferenceIfMissing(Program program, Address from, Address to) {
		ReferenceManager refMgr = program.getReferenceManager();
		boolean exists = false;
		for (Reference ref : refMgr.getReferencesFrom(from)) { // returns Reference[]
			if (!ref.isMemoryReference()) {
				continue;
			}
			if (ref.getToAddress().equals(to) && ref.getReferenceType().isCall()) {
				exists = true;
				break;
			}
		}
		if (!exists) {
			refMgr.addMemoryReference(from, to, FlowType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 1);
		}
	}

	// New method for analyzing a decompiled function
	private AnalysisStats analyzeDecompiledFunction(Function f, DecompileResults res, Program program) {

		// Read options
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		enableFunctionClosure = options.getBoolean(OPTION_ENABLE_FUNCTION_CLOSURE, true);
		enableIndirectCall = options.getBoolean(OPTION_ENABLE_INDIRECT_CALL, true);
		printStats = options.getBoolean(OPTION_ENABLE_PRINT_STATS, false);

		Memory mem = program.getMemory();


		AnalysisStats stats = new AnalysisStats();
		stats.numberOfFunctions = 1;
		if (res != null) {
			stats.successfulDecompilations = 1;
			HighFunction hf = res.getHighFunction();
			if (hf != null) {
				stats.successfulFunctionAnalyses = 1;
				Iterator<PcodeOpAST> it = hf.getPcodeOps();
				while (it.hasNext()) {
					PcodeOp op = it.next();

					boolean enablePutByIdTracking = true;

					if (enablePutByIdTracking) {
						if (op.getOpcode() == PcodeOp.CALLOTHER) {
							String uname = callotherToString(op, program);
							if (uname.equals("putById") || uname.equals("putNewOwnById")) {
								// count names of the field
								Varnode object = op.getInput(1);
								PcodeOp objectDef = traceOpcode(object);
								String sourceName = objectDef != null ? objectDef.getMnemonic() : "<unresolved>";
								if (sourceName.equals("CALLOTHER")) {
									String uname2 = callotherToString(objectDef, program);
									if(uname2.equals("getById")) {
										// analyze getById to extract field name
										GetByIdResult getByIdResult = analyzeGetById(objectDef, program);
										if (getByIdResult.pcodeOp != null) {
											sourceName = "GETBYID:" + getByIdResult.fieldName;
										} else if( getByIdResult.objectString != null ) {
											sourceName = "GETBYIDOBJ:" + getByIdResult.objectString;
										} else {
											sourceName = "GETBYID:<unresolved>";
										}

										
									} else {
										sourceName = "CALLOTHER:" + uname2;
									}
								}
								if (sourceName.startsWith("<unresolved>")) {
								}
								stats.putByIdCount.put(sourceName, stats.putByIdCount.getOrDefault(sourceName, 0) + 1);

							}
						}
					}


					if (enableFunctionClosure) {
						if (op.getOpcode() == PcodeOp.PTRSUB) {
							for (Varnode input : op.getInputs()) {
								if (input.isConstant()) {
									Address resolvedAddr = resolveVarnodeAddress(program, input);
									// check if resolvedAddr points to a function entry
									if (resolvedAddr != null) {
										MemoryBlock functionBlock = mem.getBlock("Function Code");
										if (functionBlock != null && functionBlock.contains(resolvedAddr)) {
											stats.foundFunctionReference++;
											if (op.getOutput() != null) {
												
												Varnode output = op.getOutput();
												output.getDescendants().forEachRemaining(descendantOp -> {
													if (descendantOp.getOpcode() == PcodeOp.STORE) {
														Varnode objectVn = descendantOp.getInput(1);
														PcodeOp objectDef = traceOpcode(objectVn);
														if (objectDef == null) {
															stats.closureCount.put("<unresolved>",
																stats.closureCount.getOrDefault("<unresolved>", 0) + 1);
															return;
														}

														if (objectDef.getOpcode() == PcodeOp.CALLOTHER) {
															String uname = callotherToString(objectDef, program);
															if (uname.equals("putById") || uname.equals("putNewOwnById")) {
																uname = "putById";
																// count names of the field
																Varnode fieldNameVn = objectDef.getInput(2);
																PcodeOp fieldNameDef = traceOpcode(fieldNameVn);

																if (fieldNameDef != null && fieldNameDef.getMnemonic().equals("COPY")) {
																	Varnode fieldNamePtrVn = fieldNameDef.getInput(0);
																	Address fieldNameAddr = resolveVarnodeAddress(program, fieldNamePtrVn);
																	String fieldName = readCString(program, fieldNameAddr, 256);
																	stats.closureCount.put(uname + ":" + fieldName, stats.closureCount.getOrDefault(uname + ":" + fieldName, 0) + 1);

																	if (fieldAddressPutCache.containsKey(fieldName)) {
																		fieldAddressPutCache.put(fieldName, null);
																	} else {
																		fieldAddressPutCache.put(fieldName, resolvedAddr);
																	}
																} else {
																	String fieldNameMnemonic =
																		fieldNameDef == null ? "<null>" : fieldNameDef.getMnemonic();
																	logWarn("Traced field name opcode: " + fieldNameMnemonic);
																}														

																// get origin of first input
																Varnode firstInput = objectDef.getInput(1);
																PcodeOp tracedOpcode = traceOpcode(firstInput);
																if (tracedOpcode != null && tracedOpcode.getOpcode() == PcodeOp.CALLOTHER) {
																	String uname2 = callotherToString(tracedOpcode, program);
																	stats.closureCount.put(uname + ":" + uname2, stats.closureCount.getOrDefault(uname + ":" + uname2, 0) + 1);
																} else if (tracedOpcode != null) {
																	stats.closureCount.put(uname + ":" + tracedOpcode.getMnemonic(), stats.closureCount.getOrDefault(uname + ":" + tracedOpcode.getMnemonic(), 0) + 1);
																} else {
																	stats.closureCount.put(uname + ":<unresolved>", stats.closureCount.getOrDefault(uname + ":<unresolved>", 0) + 1);
																}
															} else {
																stats.closureCount.put(uname, stats.closureCount.getOrDefault(uname, 0) + 1);
															}
														} else {
															String mnemonic = objectDef == null ? "<unresolved>" : objectDef.getMnemonic();
															logWarn("Non-CALLOTHER descendant: " + mnemonic);
															stats.closureCount.put(mnemonic, stats.closureCount.getOrDefault(mnemonic, 0) + 1);
														}
													}
												});
											}
										}
									}
								}							
							}
						}
					}

					// analyze origin of all indirect calls
					if (enableIndirectCall) {
						if (op.getOpcode() == PcodeOp.CALLIND) {
							stats.functionCallsTotal++;
							Varnode vn = op.getInput(0);
							if (vn.isAddress()) {
								stats.callNotFromGetById++;
								// check if address points to a function
								Address callAddr = vn.getAddress();
								Function callFunc = program.getFunctionManager().getFunctionAt(callAddr);
								if (callFunc == null) {
									throw new IllegalStateException("Indirect call target address " + callAddr + " is not a function at: " + op.getSeqnum().getTarget());
								}
							} else {
								PcodeOp def = vn.getDef();
								if (def != null) {
									PcodeOp traced = traceCallOther(vn);
									if (traced != null && traced != def) {
										String uname = callotherToString(traced, program);
										if (uname != null && uname.toLowerCase().startsWith("getbyid")) {

											// Recover string and opcode as a pair
											HeatmapEntry entry;
											GetByIdResult result = analyzeGetById(traced, program);
											
											PcodeOp opcodeDef = result.pcodeOp;
											if (opcodeDef != null) {
												int opcode = opcodeDef.getOpcode();
												String opname = PcodeOp.getMnemonic(opcode);
												if (opname != null && opname.equals("CALLOTHER")) {
													// Get userop name from first input (usually index)
													String useropName = callotherToString(opcodeDef, program);
													if (useropName.toLowerCase().startsWith("getbyid")) {
														GetByIdResult resultFromObject = analyzeGetById(opcodeDef, program);
														if (resultFromObject.pcodeOp != null) {
															int opcode2 = resultFromObject.pcodeOp.getOpcode();
															String opname2 = PcodeOp.getMnemonic(opcode2);
															if (opname2 != null && opname2.equals("CALLOTHER")) {
																String useropName2 = callotherToString(resultFromObject.pcodeOp, program);
																if (useropName2.toLowerCase().startsWith("getbyid")) {
																	GetByIdResult resultFromObject2 = analyzeGetById(resultFromObject.pcodeOp, program);
																	if (resultFromObject2.pcodeOp != null) {
																		String useropName3 = callotherToString(resultFromObject2.pcodeOp, program);
																		entry = new HeatmapEntry(result.fieldName, resultFromObject.fieldName, resultFromObject2.fieldName + ":" + useropName3);
																	} else if (resultFromObject2.pcodeOp == null && resultFromObject2.objectString != null) {
																		entry = new HeatmapEntry(result.fieldName, resultFromObject.fieldName, resultFromObject2.fieldName + ":" + resultFromObject2.objectString);
																		if (resultFromObject2.objectString.equals("<global_register>")) {
																			String chainKey = result.fieldName + "|" + resultFromObject.fieldName + "|" + resultFromObject2.fieldName +"|<global_register>";
																			stats.globalRegisterHeatmap.put(chainKey, stats.globalRegisterHeatmap.getOrDefault(chainKey, 0) + 1);
																			createGlobalFunction("global." + resultFromObject2.fieldName + "." + resultFromObject.fieldName + "." + result.fieldName, traced.getSeqnum().getTarget(), op.getSeqnum().getTarget(), program);
																		}
																	} else {
																		entry = new HeatmapEntry(result.fieldName, resultFromObject.fieldName, "getById:<unresolved>");
																	}
																} else {
																	entry = new HeatmapEntry(result.fieldName, resultFromObject.fieldName, useropName2);
																}
															} else if (opname2 != null && opname2.equals("INDIRECT")) {
																entry = new HeatmapEntry(result.fieldName, resultFromObject.fieldName, resultFromObject.objectString);
															} else {
																entry = new HeatmapEntry(result.fieldName, resultFromObject.fieldName, opname2);
															}
														} else if (resultFromObject.pcodeOp == null && resultFromObject.objectString != null) {
															entry = new HeatmapEntry(result.fieldName, resultFromObject.fieldName, resultFromObject.objectString);
															if (resultFromObject.objectString.equals("<global_register>")) {
																String chainKey = result.fieldName + "|" + resultFromObject.fieldName + "|<global_register>";
																stats.globalRegisterHeatmap.put(chainKey, stats.globalRegisterHeatmap.getOrDefault(chainKey, 0) + 1);
																createGlobalFunction("global." + resultFromObject.fieldName + "." + result.fieldName, traced.getSeqnum().getTarget(), op.getSeqnum().getTarget(), program);
															}
														} else {
															entry = new HeatmapEntry(result.fieldName, resultFromObject.fieldName, "<unresolved>");
														}
													} else {
														entry = new HeatmapEntry(result.fieldName, useropName, "<non-getById>");
													}											
												} else if (opname != null && opname.equals("INDIRECT")) {
													entry = new HeatmapEntry(result.fieldName, result.objectString, "<non-CALLOTHER>");
												}
												else {
													entry = new HeatmapEntry(result.fieldName, opname, "<non-CALLOTHER>");
												}
												stats.callFromGetById++;
											} else if (result.pcodeOp == null && result.objectString != null) {
												entry = new HeatmapEntry(result.fieldName, result.objectString, "<non-CALLOTHER>");
												if (result.objectString.equals("<global_register>")) {
													String chainKey = result.fieldName + "|<global_register>";
													stats.globalRegisterHeatmap.put(chainKey, stats.globalRegisterHeatmap.getOrDefault(chainKey, 0) + 1);
													createGlobalFunction("global." + result.fieldName, traced.getSeqnum().getTarget(), op.getSeqnum().getTarget(), program);
												}
											} else {
												entry = new HeatmapEntry(result.fieldName, "<unresolved>", "<non-CALLOTHER>");

														logWarn("Unresolved getById call target in function '" + f.getName() +
															"' at " + op.getSeqnum().getTarget() +
															" field=" + result.fieldName + " object=" + result.objectString);
												stats.callNotFromGetById++;
											}
											stats.heatmap.put(entry, stats.heatmap.getOrDefault(entry, 0) + 1);
											
											stats.indirectCallsFromGetById++;
										} else if (uname != null) {
											stats.callotherCounts.put(uname, stats.callotherCounts.getOrDefault(uname, 0) + 1);
										} else {
											logWarn("Encountered CALLOTHER with unresolved userop name in function '" +
												f.getName() + "' at " + op.getSeqnum().getTarget());
										}
									} else {
										PcodeOp tracedOpcode = traceOpcode(vn);
										if (tracedOpcode != null) {
											int opcode = tracedOpcode.getOpcode();
											String opname = PcodeOp.getMnemonic(opcode);
											stats.opcodeCounts.put(opname, stats.opcodeCounts.getOrDefault(opname, 0) + 1);
										} else {
											stats.opcodeCounts.put("<unresolved>", stats.opcodeCounts.getOrDefault("<unresolved>", 0) + 1);
										}
									}
								} else {
									logWarn("Could not resolve CALLIND varnode in function '" + f.getName() +
										"' at " + op.getSeqnum().getTarget() + ": " + vn);
								}
							}
						}
					}
				}
			} else {
				logWarn("Decompilation failed: no HighFunction for '" + f.getName() + "'");
			}
			String errMsg = res.getErrorMessage();
			if (errMsg != null && !errMsg.isEmpty()) {
				logWarn("Decompilation warnings/errors: " + errMsg);
			}
		} else {
			logWarn("Decompilation failed: null results");
		}
		return stats;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// Enable by default – low cost single-pass counter
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		String langId = program.getLanguageID().getIdAsString();
		return langId.startsWith("hermes:");
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_ENABLE_FUNCTION_CLOSURE, true, null,
			"Enable function closure analysis (default: on)");
		options.registerOption(OPTION_ENABLE_INDIRECT_CALL, true, null,
			"Enable indirect call analysis (default: on)");
		options.registerOption(OPTION_ENABLE_PRINT_STATS, false, null,
			"Print analysis statistics to console (default: off)");
	}

	@Override
    public void optionsChanged(Options options, Program program) {
		enableFunctionClosure = options.getBoolean(OPTION_ENABLE_FUNCTION_CLOSURE, true);
		enableIndirectCall = options.getBoolean(OPTION_ENABLE_INDIRECT_CALL, true);
        printStats = options.getBoolean(OPTION_ENABLE_PRINT_STATS, false);
    }

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		logInfo("added() start program=" + program.getName());
		// Ensure helper block exists early so subsequent global stub creations succeed
		ensureHelperBlock(program);

		int totalFunctionsToProcess = program.getFunctionManager().getFunctionCount();
		logInfo("Total functions to process: " + totalFunctionsToProcess);

		DecompileOptions opts = new DecompileOptions();
		opts.setDefaultTimeout(120);
		opts.setMaxPayloadMBytes(512);

		// Collect all functions to decompile
		Collection<Function> allFunctions = new HashSet<>();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			allFunctions.add(f);
		}


		// Aggregate stats from all functions
		AnalysisStats totalStats = new AnalysisStats();
		QCallback<Function, AnalysisStats> callback = (Function f, TaskMonitor monitor1) -> {
			DecompInterface iface = new DecompInterface();
			iface.openProgram(program);
			iface.setOptions(opts);
			DecompileResults res = iface.decompileFunction(f, 120, monitor1);
			return analyzeDecompiledFunction(f, res, program);
		};

		try {
			ParallelDecompiler.decompileFunctions(callback, allFunctions, monitor).forEach(totalStats::merge);
		} catch (InterruptedException e) {
			throw new CancelledException("Parallel decompilation interrupted");
		} catch (Exception e) {
			throw new CancelledException("Parallel decompilation failed: " + e.getMessage());
		}

		if (printStats) {
			logInfo("Function analysis pass complete. Total functions=" + totalStats.numberOfFunctions);
			logInfo("Indirect call opcode summary (not getById):");
			for (Map.Entry<String, Integer> entry : totalStats.opcodeCounts.entrySet()) {
				logInfo("Opcode '" + entry.getKey() + "': " + entry.getValue());
			}
			logInfo("Successful decompilations=" + totalStats.successfulDecompilations);
			logInfo("Successful function analyses=" + totalStats.successfulFunctionAnalyses);
			logInfo("Calls from getById=" + totalStats.callFromGetById);
			logInfo("Calls not from getById=" + totalStats.callNotFromGetById);
			logInfo("Indirect calls whose target derived from getById=" + totalStats.indirectCallsFromGetById);
			logInfo("Total indirect function calls=" + totalStats.functionCallsTotal);
			logInfo("Found function references via closure analysis=" + totalStats.foundFunctionReference);
		}

		if (printStats) {
			logInfo("Closure call summary:");
	
			totalStats.closureCount.entrySet().stream()
				.sorted((a, b) -> Integer.compare(a.getValue(), b.getValue()))
				.forEach(entry -> logInfo("Closure " + entry.getKey() + " : " + entry.getValue()));
	
			totalStats.putByIdCount.entrySet().stream()
				.sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
				.forEach(entry -> logInfo("putById source " + entry.getKey() + " : " + entry.getValue()));
		}

		// Iterate all instructions in the specified set
		Listing listing = program.getListing();
		InstructionIterator iter = listing.getInstructions(set, true);

		while (iter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = iter.next();

			if (enableIndirectCall) {
				if (!instr.getFlowType().isCall()) {
					continue;
				}
				Address[] flows = instr.getFlows();

				for (Address target : flows) {
					Function tf = program.getFunctionManager().getFunctionAt(target);
					if (tf != null && tf.getEntryPoint().equals(target)) {
						// Heuristic exclusion: ignore function-table-like synthetic functions by name
						String name = tf.getName();
						boolean looksLikeTableEntry = name.startsWith("func_") && name.contains("table");
						if (!looksLikeTableEntry) {
							// Intentionally no aggregation here yet; this pass currently serves call filtering.
						}
					}
				}
			}
		}

		return true;
	}
}
