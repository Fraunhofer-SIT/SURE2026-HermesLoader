package hermesloader;

import java.util.HashMap;
import java.util.Map;

public class AnalysisStats {
    public int foundFunctionReference = 0;
    public int numberOfFunctions = 0;
    public int successfulDecompilations = 0;
    public int successfulFunctionAnalyses = 0;
    public int functionCallsTotal = 0;
    public int callFromGetById = 0;
    public int callNotFromGetById = 0;
    public int indirectCallsFromGetById = 0;
    public Map<String, Integer> opcodeCounts = new HashMap<>();
    public Map<String, Integer> callotherCounts = new HashMap<>();
    public Map<String, Integer> closureCount = new HashMap<>();
    public Map<String, Integer> putByIdCount = new HashMap<>();
    public Map<HeatmapEntry, Integer> heatmap = new HashMap<>();
    // Heatmap for chains that terminate in the global register object
    // Key format: fieldName1|fieldName2|...|<global_register>
    public Map<String, Integer> globalRegisterHeatmap = new HashMap<>();

    public void merge(AnalysisStats other) {
        foundFunctionReference += other.foundFunctionReference;
        numberOfFunctions += other.numberOfFunctions;
        successfulDecompilations += other.successfulDecompilations;
        successfulFunctionAnalyses += other.successfulFunctionAnalyses;
        functionCallsTotal += other.functionCallsTotal;
        callFromGetById += other.callFromGetById;
        callNotFromGetById += other.callNotFromGetById;
        indirectCallsFromGetById += other.indirectCallsFromGetById;
        for (Map.Entry<String, Integer> e : other.closureCount.entrySet()) {
            closureCount.put(e.getKey(), closureCount.getOrDefault(e.getKey(), 0) + e.getValue());
        }
        for (Map.Entry<String, Integer> e : other.opcodeCounts.entrySet()) {
            opcodeCounts.put(e.getKey(), opcodeCounts.getOrDefault(e.getKey(), 0) + e.getValue());
        }
        for (Map.Entry<String, Integer> e : other.callotherCounts.entrySet()) {
            callotherCounts.put(e.getKey(), callotherCounts.getOrDefault(e.getKey(), 0) + e.getValue());
        }
        for (Map.Entry<HeatmapEntry, Integer> e : other.heatmap.entrySet()) {
            heatmap.put(e.getKey(), heatmap.getOrDefault(e.getKey(), 0) + e.getValue());
        }
        for (Map.Entry<String, Integer> e : other.globalRegisterHeatmap.entrySet()) {
            globalRegisterHeatmap.put(e.getKey(), globalRegisterHeatmap.getOrDefault(e.getKey(), 0) + e.getValue());
        }
        for (Map.Entry<String, Integer> e : other.putByIdCount.entrySet()) {
            putByIdCount.put(e.getKey(), putByIdCount.getOrDefault(e.getKey(), 0) + e.getValue());
        }
    }
}
