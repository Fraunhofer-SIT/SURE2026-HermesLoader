package hermesloader.inject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import hermesloader.HermesLoaderAnalyzer;

public class InjectPayloadHermesGetById extends InjectPayloadCallother {

	public InjectPayloadHermesGetById(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		if( HermesLoaderAnalyzer.globalFieldAddressCache.containsKey(con.baseAddr) ) {
			Address fAddr = HermesLoaderAnalyzer.globalFieldAddressCache.get(con.baseAddr);
			Varnode output = con.output.get(0);
			int size = output.getSize();
			
			AddressFactory af = program.getAddressFactory();
			// use a constant address, otherwise ghidra will represent the call like
			// "uVar2 = (*_global.JSON.stringify)(uVar8,uVar7);" and use variables
			Address constAddr = af.getConstantAddress(fAddr.getOffset());

			Varnode constVn = new Varnode(constAddr, size);

			PcodeOp op = new PcodeOp(con.baseAddr, 0, PcodeOp.COPY);
			op.setInput(constVn, 0);
			op.setOutput(output);

			return new PcodeOp[] { op };
		}

		return singlePutHeuristic(program, con);
	}

	private PcodeOp[] singlePutHeuristic(Program program, InjectContext con) {
		Varnode fieldName = con.inputlist.get(1);
		String resolvedFieldName;
		Address strPtrAddr = null;
		if (fieldName.isUnique()) {
			
			Instruction ins = program.getListing().getInstructionAt(con.baseAddr);
			PcodeOp[] ops = ins.getPcode();

			for (PcodeOp op : ops) {
				Varnode out = op.getOutput();
				if (out != null && out.isUnique() && out.getOffset() == fieldName.getOffset()) {
					if (op.getOpcode() == PcodeOp.LOAD) {
						fieldName = op.getInput(1);
						if (fieldName.isConstant()) {
							Address fAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(fieldName.getOffset());
							strPtrAddr = HermesLoaderAnalyzer.readPointer(program, fAddr);
							break;
						}						
					}
				}
			}
		} else if (fieldName.isConstant()) {
			strPtrAddr = HermesLoaderAnalyzer.resolveVarnodeAddress(program, fieldName);
		} else {
			throw new UnsupportedOperationException("Unsupported fieldName varnode type: " + fieldName.toString());
		}

		// read pointer
		if (strPtrAddr != null) {
			String s = HermesLoaderAnalyzer.readCString(program, strPtrAddr, 256);
			resolvedFieldName = s != null ? s : "<unresolved>";
		} else {
			resolvedFieldName = "<unresolvedAddr>";
		}

		if (HermesLoaderAnalyzer.fieldAddressPutCache.containsKey(resolvedFieldName)) {
				Address fAddr = HermesLoaderAnalyzer.fieldAddressPutCache.get(resolvedFieldName);
				if (fAddr != null) {
					Varnode output = con.output.get(0);
					int size = output.getSize();

					AddressFactory af = program.getAddressFactory();
					// use a constant address, otherwise ghidra will represent the call like
					// "uVar2 = (*_global.JSON.stringify)(uVar8,uVar7);" and use variables
					Address constAddr = af.getConstantAddress(fAddr.getOffset());

					Varnode constVn = new Varnode(constAddr, size);

					PcodeOp op = new PcodeOp(con.baseAddr, 0, PcodeOp.COPY);
					op.setInput(constVn, 0);
					op.setOutput(output);

					return new PcodeOp[] { op };
				}
		}
		
		// Fall back to the original userop when the heuristic cannot resolve a direct target.
		PcodeOp op = new PcodeOp(con.baseAddr, 0, PcodeOp.CALLOTHER);
		// First input: constant identifying the userop
		AddressFactory af = program.getAddressFactory();
		int callotherId = getUserOpIdByName(program, "getById");
		Varnode idVn = new Varnode(af.getConstantAddress(callotherId), 1);
		op.setInput(idVn, 0);
		for (int i = 0; i < con.inputlist.size(); i++) {
			op.setInput(con.inputlist.get(i), i+1);
		}
		for (int i = 0; i < con.output.size(); i++) {
			op.setOutput(con.output.get(i));
		}
		return new PcodeOp[] { op };
	}

	public static int getUserOpIdByName(Program program, String userOpName) {
		Language lang = program.getLanguage();
		boolean hasNext = true;
		int i = 0;
		while (hasNext) {
			String userOps = lang.getUserDefinedOpName(i);
			if (userOps == null) {
				return -1;
			}
			if (userOps.equals(userOpName)) {
				return i; // this i is the CALLOTHER id
			}
			i++;
		}
		return -1; // not found
	}
}