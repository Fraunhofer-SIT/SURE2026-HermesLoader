package hermesloader;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import hermesloader.parser.HbcBinaryStructs.HbcString;

public class HermesStringUtil {
    public static void createHermesStringBlock(Program program, FlatProgramAPI api, Memory mem, TaskMonitor monitor, List<HbcString> allStrings) throws Exception {
		    if (allStrings == null || allStrings.isEmpty()) {
	            throw new IllegalArgumentException("'all_strings' is missing or not an array");
	        }
		    
		    // The strings do overlap, we need to sort so the algorithm is easier
		    List<HbcString> sorted = new ArrayList<>();
		    allStrings.forEach(sorted::add);
		    sorted.sort(Comparator.comparingInt(n -> ((HbcString)n).length).reversed());


	        for (HbcString n : sorted) {
	        	// String string = n.value;
	        	int address = n.address;
	        	int length = n.length;

	            if (length > 0) {
	            	
	            	Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
	            	int addrLength;
	            	Address addr_tmp;
	            	boolean isStartDefined;
	            	for(int i = 0; i < length; i++) {
	            		addr_tmp = addr.add(i);
	            		addrLength = length - i;
	            		isStartDefined = !DataUtilities.isUndefinedRange(program, addr_tmp, addr_tmp);
		            	if (!isStartDefined) {
		            		Data nextDefinitionData = DataUtilities.getNextNonUndefinedDataAfter(program, addr_tmp, addr_tmp.add(addrLength));
		            		if (nextDefinitionData == null) {
			            		DataUtilities.createData(program, addr_tmp, new StringDataType(), addrLength, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
			            		break;
		            		}
	            			Address nextDefinition = nextDefinitionData.getAddress();
		            		int offsetNextDefinition = Math.toIntExact(nextDefinition.subtract(addr_tmp));
		            		if (offsetNextDefinition < addrLength) {
		            			DataUtilities.createData(program, addr_tmp, new StringDataType(), offsetNextDefinition, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
		            			break;
		            		}
		            		DataUtilities.createData(program, addr_tmp, new StringDataType(), addrLength, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
		            		break;		            		
		            	}
	            	}
	            }
	        }
    }
}
