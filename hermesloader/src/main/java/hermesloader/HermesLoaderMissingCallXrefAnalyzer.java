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

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import generic.concurrent.QCallback;
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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Hermes Missing Call Xref Analyzer
 * <p>
 * Decompile-driven pass that scans each function's HighFunction pcode for indirect call
 * operations (CALLIND) which do not yet have a call reference (xref) to a known function
 * entry. When it can conservatively resolve the target to a function entry, it adds an
 * UNCONDITIONAL_CALL memory reference so later analyses have stable incoming call edges.
 * <p>
 * Resolution strategy:
 * <ol>
 *   <li>Identify instructions whose flow type is a call but have zero flows resolved by Ghidra.</li>
 *   <li>Within those instructions, locate a CALLIND pcode op.</li>
 *   <li>Trace simple producer chain of the first input varnode (COPY/CAST/INDIRECT) to a constant/address.</li>
 *   <li>If the resolved address matches an existing function entry, add a call reference if none exists.</li>
 * </ol>
 * The analyzer purposefully keeps the trace shallow and conservative to avoid creating
 * incorrect xrefs.
 */
public class HermesLoaderMissingCallXrefAnalyzer extends AbstractAnalyzer {
    private static final String LOG_PREFIX = "[HermesLoaderMissingCallXrefAnalyzer] ";

    private static void logInfo(String message) {
        Msg.info(HermesLoaderMissingCallXrefAnalyzer.class, LOG_PREFIX + message);
    }

    private static void logWarn(String message) {
        Msg.warn(HermesLoaderMissingCallXrefAnalyzer.class, LOG_PREFIX + message);
    }

    // Option keys
    private static final String OPTION_MAX_TRACE_DEPTH = "Max Producer Trace Depth";
    private static final String OPTION_VERBOSE_LOG = "Verbose Logging";
    private static final String OPTION_DECOMPILE_TIMEOUT = "Decompile Timeout (sec)";
    private static final String OPTION_MAX_PAYLOAD_MB = "Decompile Max Payload (MB)";

    // Defaults
    private int maxTraceDepth = 8;
    private boolean verbose = false;
    private int decompileTimeoutSec = 60;
    private int decompileMaxPayloadMB = 256;

    public HermesLoaderMissingCallXrefAnalyzer() {
        super("Hermes Missing Call Xrefs", "Adds missing call xrefs for resolvable indirect calls in Hermes programs.", AnalyzerType.INSTRUCTION_ANALYZER);
        // Run after basic coverage analyzer so we don't interfere with its raw counts.
        setPriority(AnalysisPriority.LOW_PRIORITY.before());
    }

    @Override
    public boolean canAnalyze(Program program) {
        String langId = program.getLanguageID().getIdAsString();
        return langId.startsWith("hermes:");
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return false;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPTION_MAX_TRACE_DEPTH, maxTraceDepth, null, "Maximum number of simple producer steps (COPY/CAST/INDIRECT) to follow (default: 8)");
        options.registerOption(OPTION_VERBOSE_LOG, verbose, null, "Emit verbose logging for each recovered xref (default: off)");
        options.registerOption(OPTION_DECOMPILE_TIMEOUT, decompileTimeoutSec, null, "Per-function decompile timeout in seconds (default: 60)");
        options.registerOption(OPTION_MAX_PAYLOAD_MB, decompileMaxPayloadMB, null, "Decompiler max payload size in MB (default: 256)");
    }

    private void loadOptions(Program program) {
        Options options = program.getOptions(getName());
        maxTraceDepth = options.getInt(OPTION_MAX_TRACE_DEPTH, maxTraceDepth);
        verbose = options.getBoolean(OPTION_VERBOSE_LOG, verbose);
        decompileTimeoutSec = options.getInt(OPTION_DECOMPILE_TIMEOUT, decompileTimeoutSec);
        decompileMaxPayloadMB = options.getInt(OPTION_MAX_PAYLOAD_MB, decompileMaxPayloadMB);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        loadOptions(program);
        logInfo("Starting decompile-based missing call xref recovery for program=" + program.getName());

        ReferenceManager refMgr = program.getReferenceManager();

        // Collect all functions inside the provided address set
        Collection<Function> functions = new HashSet<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (set.contains(f.getEntryPoint())) {
                functions.add(f);
            }
        }

        DecompileOptions opts = new DecompileOptions();
        opts.setDefaultTimeout(decompileTimeoutSec);
        opts.setMaxPayloadMBytes(decompileMaxPayloadMB);

        long totalFunctions = functions.size();
        AtomicLong processedFunctions = new AtomicLong();
        AtomicLong totalIndirectCallOps = new AtomicLong();
        AtomicLong unresolvedIndirectCallOps = new AtomicLong(); // CALLIND without existing call reference
        AtomicLong recoveredXrefs = new AtomicLong();
        AtomicLong alreadyHadReference = new AtomicLong();
        AtomicLong failedResolution = new AtomicLong();
        Set<Address> recoveredTargets = new HashSet<>(); // shared set; low contention expected

        QCallback<Function, Long> callback = (Function func, TaskMonitor m) -> {
            DecompInterface iface = new DecompInterface();
            iface.setOptions(opts);
            iface.openProgram(program);
            DecompileResults res = iface.decompileFunction(func, decompileTimeoutSec, m);
            HighFunction hf = res.getHighFunction();
            if (hf == null) {
                return 0L; // nothing done
            }

            long localRecovered = 0;
            Iterator<PcodeOpAST> it = hf.getPcodeOps();
            while (it.hasNext()) {
                PcodeOpAST op = it.next();
                if (op.getOpcode() != PcodeOp.CALLIND) {
                    continue;
                }
                totalIndirectCallOps.incrementAndGet();
                Address fromAddr = op.getSeqnum().getTarget();

                // Determine if a call reference already exists from instruction to any function
                boolean hasCallRef = false;
                for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                    if (ref.getReferenceType().isCall()) {
                        hasCallRef = true;
                        break;
                    }
                }
                if (hasCallRef) {
                    alreadyHadReference.incrementAndGet();
                    continue;
                }
                unresolvedIndirectCallOps.incrementAndGet();

                if (op.getNumInputs() == 0) {
                    failedResolution.incrementAndGet();
                    continue;
                }
                Varnode targetVn = op.getInput(0);
                Address resolved = resolveToAddress(program, targetVn, maxTraceDepth, new HashSet<>());
                if (resolved == null) {
                    failedResolution.incrementAndGet();
                    continue;
                }
                Function targetFunc = program.getFunctionManager().getFunctionAt(resolved);
                if (targetFunc == null || !targetFunc.getEntryPoint().equals(resolved)) {
                    failedResolution.incrementAndGet();
                    continue; // not a function entry
                }

                // Add call reference
                try {
                    Reference newRef = refMgr.addMemoryReference(fromAddr, resolved, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 1);
                    refMgr.setPrimary(newRef, true);
                    recoveredXrefs.incrementAndGet();
                    localRecovered++;
                    recoveredTargets.add(resolved);
                    if (verbose) {
                        logInfo("Added call xref " + fromAddr + " -> " + resolved + " (" + targetFunc.getName() + ")");
                    }
                } catch (Exception e) {
                    failedResolution.incrementAndGet();
                    if (verbose) {
                        logWarn("Failed to add reference: " + e.getMessage());
                    }
                }
            }
            processedFunctions.incrementAndGet();
            return localRecovered;
        };

        try {
            ParallelDecompiler.decompileFunctions(callback, functions, monitor);
        } catch (InterruptedException e) {
            throw new CancelledException("Decompile interrupted");
        } catch (Exception e) {
            throw new CancelledException("Parallel decompilation failed: " + e.getMessage());
        }

    logInfo("Processed functions=" + processedFunctions.get() + "/" + totalFunctions);
    logInfo("CALLIND ops total=" + totalIndirectCallOps.get());
    logInfo("CALLIND ops lacking call ref=" + unresolvedIndirectCallOps.get());
    logInfo("Recovered call xrefs=" + recoveredXrefs.get());
    logInfo("Distinct recovered targets=" + recoveredTargets.size());
    logInfo("Already had call reference=" + alreadyHadReference.get());
    logInfo("Failed resolutions=" + failedResolution.get());

    log.appendMsg(getName(), "Recovered call xrefs: " + recoveredXrefs.get() + "/" + unresolvedIndirectCallOps.get() + " unresolved CALLIND ops");
    log.appendMsg(getName(), "Distinct recovered targets: " + recoveredTargets.size());
    log.appendMsg(getName(), "Already had reference: " + alreadyHadReference.get() + "; Failures: " + failedResolution.get());

        return true;
    }

    /**
     * Attempt to resolve a varnode to a concrete address by following a limited chain of
     * simple producers (COPY, CAST, INDIRECT). Stops at first constant/address varnode.
     */
    private Address resolveToAddress(Program program, Varnode start, int budget, Set<Varnode> visited) {
        if (start == null || budget <= 0 || visited.contains(start)) {
            return null;
        }
        visited.add(start);
        if (start.isAddress()) {
            return start.getAddress();
        }
        if (start.isConstant()) {
            // Interpret constant as default address space offset
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(start.getOffset());
        }

        PcodeOp def = start.getDef();
        if (def == null) {
            return null;
        }
        int opcode = def.getOpcode();

        if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.INDIRECT) {
            if (def.getNumInputs() > 0) {
                return resolveToAddress(program, def.getInput(0), budget - 1, visited);
            }
        }
        return null; // give up if producer is not a simple pass-through
    }
}
