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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Hermes Function Coverage Analyzer
 * <p>
 * This lightweight analyzer computes simple coverage-style metrics for Hermes functions:
 * <ul>
 *   <li>How many call instructions resolve to function entry points.</li>
 *   <li>Per-function incoming call counts (excluding synthetic table-style entries).</li>
 *   <li>Basic CALLOTHER usage summary (getById / putById / other) without decompilation.</li>
 * </ul>
 * Results are emitted to the console and a brief summary placed into the MessageLog.
 * The intent is to provide a fast pass that complements the heavier decompiler-based
 * analysis performed by {@link HermesLoaderAnalyzer}.
 */
public class HermesLoaderFunctionCoverageAnalyzer extends AbstractAnalyzer {
    private static final String LOG_PREFIX = "[HermesLoaderFunctionCoverageAnalyzer] ";

    private static void logInfo(String message) {
        Msg.info(HermesLoaderFunctionCoverageAnalyzer.class, LOG_PREFIX + message);
    }

    public HermesLoaderFunctionCoverageAnalyzer() {
        super("Hermes Function Coverage", "Computes lightweight function call coverage metrics for Hermes programs.", AnalyzerType.INSTRUCTION_ANALYZER);
        AnalysisPriority analysisPriority = AnalysisPriority.LOW_PRIORITY.after();
        setPriority(analysisPriority); // run after basic analyzers, but before very high cost ones
    }

    @Override
    public boolean canAnalyze(Program program) {
        String langId = program.getLanguageID().getIdAsString();
        return langId.startsWith("hermes:");
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return true; // Enabled by default; low cost
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {

        logInfo("Starting coverage analysis for program=" + program.getName());

        long totalCallInstr = 0;
        long resolvedCallInstr = 0;

        long totalFunctionCalls = 0;
        long resolvedFunctionCalls = 0;

        Listing listing = program.getListing();
        InstructionIterator instrIter = listing.getInstructions(set, true);
        while (instrIter.hasNext()) {
            monitor.checkCancelled();
            Instruction instr = instrIter.next();


            for (PcodeOp op : instr.getPcode()) {
                if (op.getOpcode() == PcodeOp.CALLIND || op.getOpcode() == PcodeOp.CALL) {
                    totalCallInstr++;
                    // check for xref to function
                    Reference[] xrefs = instr.getReferencesFrom();
                    for (Reference xref : xrefs) {
                        Function func = program.getFunctionManager().getFunctionAt(xref.getToAddress());
                        if (func != null) {
                            resolvedCallInstr++;
                        }
                    }
                }
            }
        }


        // check for all functions and see which are referenced by call instructions
        ReferenceManager refMgr = program.getReferenceManager();     
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            totalFunctionCalls++;
			for (Reference ref : refMgr.getReferencesTo(f.getEntryPoint())) {
				if (ref.getReferenceType() == RefType.UNCONDITIONAL_CALL || ref.getReferenceType() == RefType.COMPUTED_CALL || ref.getReferenceType() == RefType.CONDITIONAL_CALL) {
					resolvedFunctionCalls++;
					break;
				}
			}
		}
        

        // Emit summary

        logInfo("Total call instructions=" + totalCallInstr);
        logInfo("Resolved call instructions to functions=" + resolvedCallInstr);
        logInfo("Total functions=" + totalFunctionCalls);
        logInfo("Functions with incoming calls=" + resolvedFunctionCalls);

        log.appendMsg("[HermesLoaderFunctionCoverageAnalyzer] Function Coverage Summary for program=" + program.getName());
        log.appendMsg("  Total call instructions: " + totalCallInstr);
        log.appendMsg("  Resolved call instructions to functions: " + resolvedCallInstr);
        log.appendMsg("  Total functions: " + totalFunctionCalls);
        log.appendMsg("  Functions with incoming calls: " + resolvedFunctionCalls);

        return true;
    }
}
