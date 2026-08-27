package hermesloader;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that builds a JSON mapping from function name to the list of
 * strings referenced within that function. It discovers strings via the
 * loader-created "String Table" → "String Data" references and then
 * looks for all xrefs to each string from code, attributing them to the
 * containing function.
 */
public class HermesLoaderFunctionStringXrefAnalyzer extends AbstractAnalyzer {
    private static final String LOG_PREFIX = "[HermesLoaderFunctionStringXrefAnalyzer] ";

    private static void logInfo(String message) {
        Msg.info(HermesLoaderFunctionStringXrefAnalyzer.class, LOG_PREFIX + message);
    }

    private static void logWarn(String message) {
        Msg.warn(HermesLoaderFunctionStringXrefAnalyzer.class, LOG_PREFIX + message);
    }

    // Keep in sync with offsets used by the loader
    private static final long OFFSET_STRING_TABLE = 0xA0000000L;

    public HermesLoaderFunctionStringXrefAnalyzer() {
        super("Hermes Function Strings JSON", "Outputs JSON mapping of functions to referenced strings.", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.LOW_PRIORITY);
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
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        monitor.setMessage("Collecting string addresses from String Table");

        ReferenceManager rm = program.getReferenceManager();

        FlatProgramAPI api = new FlatProgramAPI(program, monitor);

        Address stringTableBase = program.getAddressFactory().getDefaultAddressSpace().getAddress(OFFSET_STRING_TABLE);

        Map<String, List<String>> funcAddrToStrings = new HashMap<>();
        
        DataTypeManager dtm = program.getDataTypeManager();
        DataType struct = dtm.getDataType("/LoadedStringTableEntry");
        if (struct == null) {
            String msg = "Data type /LoadedStringTableEntry not found; skipping function-string JSON output";
            logWarn(msg);
            log.appendMsg(getName(), msg);
            return true;
        }

        Data d = api.getDataAt(stringTableBase);
        while (d != null) {
            if (monitor.isCancelled()) break;
            if (d.isStructure() && struct.equals(d.getDataType())) {

                // get all xrefs to this string
                Address strOffsetAddr = d.getAddress();
                ReferenceIterator refToData = rm.getReferencesTo(strOffsetAddr);
                for (Reference ref : refToData) {
                    Address to = ref.getToAddress();
                    Address from = ref.getFromAddress();

                    String string = HermesLoadedStringTableUtil.getStringFromLoadedStringTableEntry(program, to);

                    // get the function address of the references address
                    Function f = program.getFunctionManager().getFunctionContaining(from);
                    if (f != null) {
                        String functionAddress = f.getEntryPoint().toString();
                        funcAddrToStrings.computeIfAbsent(functionAddress, k -> new ArrayList<>()).add(string);
                    }
                }
            }
            d = api.getDataAfter(d);
        }


        // Build JSON output
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        for (Map.Entry<String, List<String>> e : funcAddrToStrings.entrySet()) {
            ArrayNode arr = mapper.createArrayNode();
            List<String> sorted = new ArrayList<>(e.getValue());
            sorted.sort(String::compareTo);
            for (String s : sorted) {
                arr.add(s);
            }
            root.set(e.getKey(), arr);
        }

        String json = root.toString();

        // Write to a file next to the program, or fallback to the user directory
        try {
            java.nio.file.Path outDir;
            outDir = java.nio.file.Paths.get(System.getProperty("user.dir"));            
            String baseName = program.getName();
            if (baseName == null || baseName.isEmpty()) {
                baseName = "hermes_program";
            }
            java.nio.file.Path outFile = outDir.resolve(baseName + "_function_strings.json");
            java.nio.file.Files.write(outFile, json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String msg = "Wrote function strings JSON to: " + outFile.toString();
            logInfo(msg);
            log.appendMsg(getName(), msg);
        } catch (Exception e) {
            String err = "Failed to write JSON file: " + e.getMessage();
            logWarn(err);
            log.appendException(e);
        }

        return true;
    }
}
