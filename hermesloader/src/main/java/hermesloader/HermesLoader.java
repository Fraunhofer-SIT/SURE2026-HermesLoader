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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import static hermesloader.HermesLoadedFunctionTableUtil.createLoadedFunctionTableEntryStruct;
import static hermesloader.HermesLoadedStringTableUtil.createLoadedStringTableEntryStruct;
import hermesloader.parser.HbcBinaryStructs;
import hermesloader.parser.HbcBinaryStructs.FunctionInfo;
import hermesloader.parser.HbcBinaryStructs.HbcString;
import hermesloader.parser.HbcParser;
import hermesloader.parser.HermesArrayBufferParser;
import hermesloader.structs.HermesFunctionSourceStruct;
import hermesloader.structs.HermesSourcesDataStruct;


/**
 * Provide class-level documentation that describes what this loader does.
 */
public class HermesLoader extends AbstractProgramWrapperLoader {

	private static final long OFFSET_STRING_DATA =  0x0A000000L;
	private static final long OFFSET_STRING_TABLE =  0xA0000000L;
	private static final long OFFSET_FUNCTION_TABLE =  0xF0000000L;

	@Override
	public String getName() {

		// Name the loader.  This name must match the name of the loader in the .opinion files.
		return "Hermes (React Native)";
	}

	@Override
	protected void load(Program program, Loader.ImporterSettings settings) throws IOException, CancelledException {
		try {
			load(settings.provider(), settings.loadSpec(), settings.options(), program, settings.monitor(), settings.log());
		}
		catch (IOException e) {
			throw e;
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.
		
		Msg.info(this, "Loaded Hermes file");
		
		if (provider.length() >= 12) {
            BinaryReader reader = new BinaryReader(provider, true); // little-endian
            long magic = reader.readNextLong();
            if (magic == 0x1F1903C103BC1FC6L) {
            	Msg.info(this, "Match");
            	
            	long version = reader.readNextUnsignedInt();
            	Msg.debug(this, "Hermes version=" + version);
            	
            	if (version == 96) {            	
	                loadSpecs.add(new LoadSpec(this, 0,
	                    new LanguageCompilerSpecPair("hermes:LE:64:v96", "default"), true));
            	}
            }
        }	

		return loadSpecs;
	}

	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// Load the bytes from 'provider' into the 'program'.
		monitor.setMessage( "Hermes Loader: Start loading" );
		Msg.debug(this, "Hermes Loader: Start loading");
		
		try {
			long length = provider.length();
	
			InputStream inputStreamForMem;
			inputStreamForMem = provider.getInputStream(0);

			InputStream inputStreamForParser;
			inputStreamForParser = provider.getInputStream(0);
			
			Memory mem = program.getMemory();
			Listing listing = program.getListing();
			ProgramModule root = listing.getRootModule(0x0);			
			
			FlatProgramAPI api = new FlatProgramAPI(program,monitor);

			int byteCounter = 0;
			// Header from Byte 0 to 128
			HermesHeaderUtil.createHermesHeader(program, api, mem, inputStreamForMem, monitor, byteCounter);
			byteCounter += 128;

			// Function Table from Byte 128 to 128 + functionCount * 120
			// (15 Byte per Function)

			byte[] data = inputStreamForParser.readAllBytes();
			HbcBinaryStructs.BytecodeFile bytecodeFile = HbcParser.readHbcFile(data);

			monitor.setMessage( "Hermes Loader: Parse HBC" );

			List<HbcString> allStrings = HbcParser.getAllStrings(bytecodeFile);
            bytecodeFile.allStrings = allStrings;

			monitor.setMessage( "Hermes Loader: Parse Strings" );

			int functionCount = bytecodeFile.bytecodeFileHeader.functionCount;

			HermesFunctionTableUtil.createHermesFunctionTable(program, api, mem, inputStreamForMem, monitor, functionCount, byteCounter);
			byteCounter += functionCount * 16;

			int stringKindCount = bytecodeFile.bytecodeFileHeader.stringKindCount;

			if (stringKindCount > 0) {
				mem.createInitializedBlock("String Kinds Table", api.toAddr(byteCounter), inputStreamForMem, stringKindCount * 4, monitor, false);
				
				// Create string kinds table entry structs
				HermesStringKindsTableUtil.createStringKindsTableStructs(program, api, mem, byteCounter, stringKindCount);
				
				byteCounter += stringKindCount * 4;
			}

			int identifierCount = bytecodeFile.bytecodeFileHeader.identifierCount;

			if (identifierCount > 0) {
				mem.createInitializedBlock("Identifier Hashes", api.toAddr(byteCounter), inputStreamForMem, identifierCount * 4, monitor, false);
				
				// Create identifier hashes table entry structs
				HermesIdentifierHashesTableUtil.createIdentifierHashesTableStructs(program, api, mem, byteCounter, identifierCount);
				
				byteCounter += identifierCount * 4;
			}

			int stringCount = bytecodeFile.bytecodeFileHeader.stringCount;

			if (stringCount > 0) {
				mem.createInitializedBlock("Small String Table", api.toAddr(byteCounter), inputStreamForMem, stringCount * 4, monitor, false);
			}
			
			// Create string table entry structs
			int overflowStringCount = bytecodeFile.bytecodeFileHeader.overflowStringCount;

			int stringStorageBase = byteCounter + (stringCount * 4) + (overflowStringCount * 8);
			int stringTableOffset = byteCounter;
			int overflowStringTableBase = stringTableOffset + (stringCount * 4);
			HermesStringTableUtil.createStringTableStructs(program, api, mem, stringTableOffset, stringCount, stringStorageBase, overflowStringTableBase);

			byteCounter += stringCount * 4;
			
			
			if(overflowStringCount > 0)
			{
				mem.createInitializedBlock("Overflow String Table", api.toAddr(byteCounter), inputStreamForMem, overflowStringCount * 8, monitor, false);
				// Create overflow string table entry structs
				HermesOverflowStringTableUtil.createOverflowStringTableStructs(program, api, mem, byteCounter, overflowStringCount, stringStorageBase);
				
				byteCounter += overflowStringCount * 8;
			}
			

			int stringStorageSize = bytecodeFile.bytecodeFileHeader.stringStorageSize;

			// Align to 4 bytes
			int padding;
			if ((byteCounter + stringStorageSize) % 4 != 0) {
				padding = 4 - ((byteCounter + stringStorageSize) % 4);
			} else {
				padding = 0;
			}

			if (stringStorageSize + padding > 0) {
				mem.createInitializedBlock("String Storage", api.toAddr(byteCounter), inputStreamForMem, stringStorageSize + padding, monitor, false);
				byteCounter += stringStorageSize;
				byteCounter += padding;
			}



			int arrayBufferSize = bytecodeFile.bytecodeFileHeader.arrayBufferSize;
			if ((byteCounter + arrayBufferSize) % 4 != 0) {
				padding = 4 - ((byteCounter + arrayBufferSize) % 4);
			} else {
				padding = 0;
			}

			MemoryBlock arrayBuffer = null;
			if (arrayBufferSize + padding > 0) {
				arrayBuffer = mem.createInitializedBlock("Array Buffer", api.toAddr(byteCounter), inputStreamForMem, arrayBufferSize + padding, monitor, false);
			}


			if (arrayBuffer != null && arrayBufferSize > 0) {
				byte[] bytesArrayBuffer = new byte[arrayBufferSize];
				arrayBuffer.getBytes(api.toAddr(byteCounter), bytesArrayBuffer);
				Address arrayBufferBaseAddr = api.toAddr(byteCounter);
				HermesArrayBufferParser.getArrayBuffer(
						bytesArrayBuffer, api, mem, arrayBufferBaseAddr);
			}

			byteCounter += arrayBufferSize;
			byteCounter += padding;



			int objKeyBufferSize = bytecodeFile.bytecodeFileHeader.objKeyBufferSize;
			// Align to 4 bytes
			if ((byteCounter + objKeyBufferSize) % 4 != 0) {
				padding = 4 - ((byteCounter + objKeyBufferSize) % 4);
			} else {
				padding = 0;
			}

			if (objKeyBufferSize + padding > 0) {
				mem.createInitializedBlock("Object Key Buffer", api.toAddr(byteCounter), inputStreamForMem, objKeyBufferSize + padding, monitor, false);
				byteCounter += objKeyBufferSize;
				byteCounter += padding;
			}



			int objValueBufferSize = bytecodeFile.bytecodeFileHeader.objValueBufferSize;
			// Align to 4 bytes
			if ((byteCounter + objValueBufferSize) % 4 != 0) {
				padding = 4 - ((byteCounter + objValueBufferSize) % 4);
			} else {
				padding = 0;
			}

			if (objValueBufferSize + padding > 0) {
				mem.createInitializedBlock("Object Value Buffer", api.toAddr(byteCounter), inputStreamForMem, objValueBufferSize + padding, monitor, false);
				byteCounter += objValueBufferSize;
				byteCounter += padding;
			}

			int bigIntCount = bytecodeFile.bytecodeFileHeader.bigIntCount;

			if(bigIntCount > 0)
			{
				// Align to 4 bytes
				if ((byteCounter + (bigIntCount * 8)) % 4 != 0) {
					padding = 4 - ((byteCounter + (bigIntCount * 8)) % 4);
				} else {
					padding = 0;
				}
				mem.createInitializedBlock("Big Int Table", api.toAddr(byteCounter), inputStreamForMem, (bigIntCount * 8) + padding, monitor, false);
				byteCounter += bigIntCount * 8;
				byteCounter += padding;
			}

			int bigIntStorageSize = bytecodeFile.bytecodeFileHeader.bigIntStorageSize;

			if(bigIntStorageSize > 0) {
				// Align to 4 bytes
				if ((byteCounter + bigIntStorageSize) % 4 != 0) {
					padding = 4 - ((byteCounter + bigIntStorageSize) % 4);
				} else {
					padding = 0;
				}
				mem.createInitializedBlock("Big Int Storage", api.toAddr(byteCounter), inputStreamForMem, bigIntStorageSize + padding, monitor, false);
				byteCounter += bigIntStorageSize;
				byteCounter += padding;
			}

			int regExpCount = bytecodeFile.bytecodeFileHeader.regExpCount;

			if(regExpCount > 0) {
				// Align to 4 bytes
				if ((byteCounter + (regExpCount * 8)) % 4 != 0) {
					padding = 4 - ((byteCounter + (regExpCount * 8)) % 4);
				} else {
					padding = 0;
				}
				mem.createInitializedBlock("Reg Exp Table", api.toAddr(byteCounter), inputStreamForMem, (regExpCount * 8) + padding, monitor, false);
				byteCounter += regExpCount * 8;
				byteCounter += padding;
			}

			int regExpStorageSize = bytecodeFile.bytecodeFileHeader.regExpStorageSize;

			if(regExpStorageSize > 0) {
				// Align to 4 bytes
				if ((byteCounter + regExpStorageSize) % 4 != 0) {
					padding = 4 - ((byteCounter + regExpStorageSize) % 4);
				} else {
					padding = 0;
				}
				mem.createInitializedBlock("Reg Exp Storage", api.toAddr(byteCounter), inputStreamForMem, regExpStorageSize + padding, monitor, false);
				byteCounter += regExpStorageSize;
				byteCounter += padding;
			}

			int cjsModuleCount = bytecodeFile.bytecodeFileHeader.cjsModuleCount;

			if(cjsModuleCount > 0) {
				// Align to 4 bytes
				if ((byteCounter + (cjsModuleCount * 8)) % 4 != 0) {
					padding = 4 - ((byteCounter + (cjsModuleCount * 8)) % 4);
				} else {
					padding = 0;
				}
				mem.createInitializedBlock("CJS Module Table", api.toAddr(byteCounter), inputStreamForMem, (cjsModuleCount * 8) + padding, monitor, false);
				byteCounter += cjsModuleCount * 8;
				byteCounter += padding;
			}

			int functionSourceCount = bytecodeFile.bytecodeFileHeader.functionSourceCount;

			if(functionSourceCount > 0) {				
				mem.createInitializedBlock("Function Source Table", api.toAddr(byteCounter), inputStreamForMem, functionSourceCount * 8, monitor, false);

				// Create function source table entry structs
				for (int i = 0; i < functionSourceCount; i++) {
					int entryOffset = byteCounter + (i * 8); // Each entry is 8 bytes
					
					StructureDataType functionSourceTableEntryStruct = HermesFunctionSourceStruct.createFunctionSourceTableEntryStruct();
					
					DataUtilities.createData(program, api.toAddr(entryOffset), functionSourceTableEntryStruct, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
					api.setPreComment(api.toAddr(entryOffset), "Function Source Table Entry " + i);

					// Add xrefs:
					//   DWORD 0: function_id -> Loaded Function Table entry at 0xF0000000 + function_id*8
					//   DWORD 1: string_id   -> Loaded String Table entry at 0xA0000000 + string_id*(4+1+4)

					ReferenceManager refMgr = program.getReferenceManager();
					// Read the two DWORDs directly from memory
					int functionId = mem.getInt(api.toAddr(entryOffset));
					int stringId = mem.getInt(api.toAddr(entryOffset + 4));

					// Validate simple bounds (non-negative)
					if (functionId >= 0 && functionId < functionCount) {
						Address funcTarget = program.getAddressFactory().getDefaultAddressSpace().getAddress(0xF0000000L + (functionId * 8L));
						refMgr.addMemoryReference(api.toAddr(entryOffset), funcTarget, RefType.DATA, SourceType.ANALYSIS, 0);
					}
					// Each loaded string table entry size is 9 bytes (4 offset + 1 isUTF16 + 4 length)
					if (stringId >= 0 && stringId < bytecodeFile.allStrings.size()) {
						Address strTarget = program.getAddressFactory().getDefaultAddressSpace().getAddress(0xA0000000L + (stringId * 9L));
						refMgr.addMemoryReference(api.toAddr(entryOffset + 4), strTarget, RefType.DATA, SourceType.ANALYSIS, 0);
					}
					
				}
			}
			byteCounter += functionSourceCount * 8;

			int debugInfoOffset = bytecodeFile.bytecodeFileHeader.debugInfoOffset;

			if (debugInfoOffset - byteCounter > 0) {
				mem.createInitializedBlock("Function Code", api.toAddr(byteCounter), inputStreamForMem, debugInfoOffset - byteCounter, monitor, false);
			}

			// create folder in program tree view
			ProgramModule debugInfoViewFolder = root.createModule("Debug Info");


			mem.createInitializedBlock("Debug Info Header", api.toAddr(debugInfoOffset), inputStreamForMem, 7 * 4, monitor, false);
			debugInfoViewFolder.reparent("Debug Info Header", root);

			
			int debugByteCounter = debugInfoOffset;
	        DataUtilities.createData(program, api.toAddr(debugByteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
	        int filenameCount = mem.getInt(api.toAddr(debugByteCounter));
	        api.setPreComment(api.toAddr(debugByteCounter), "Filename Count: " + filenameCount);
	        debugByteCounter += 4;
	        
	        DataUtilities.createData(program, api.toAddr(debugByteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
	        int filenameStorageSize = mem.getInt(api.toAddr(debugByteCounter));
	        api.setPreComment(api.toAddr(debugByteCounter), "Filename Storage Size: " + filenameStorageSize);
	        debugByteCounter += 4;
	        
	        DataUtilities.createData(program, api.toAddr(debugByteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
	        int fileRegionCount = mem.getInt(api.toAddr(debugByteCounter));
	        api.setPreComment(api.toAddr(debugByteCounter), "File Region Count: " + fileRegionCount);
	        debugByteCounter += 4;
	        
	        DataUtilities.createData(program, api.toAddr(debugByteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
	        int scopeDescDataOffset = mem.getInt(api.toAddr(debugByteCounter));
	        api.setPreComment(api.toAddr(debugByteCounter), "Scope Desc Data Offset: " + scopeDescDataOffset);
	        debugByteCounter += 4;
	        
	        DataUtilities.createData(program, api.toAddr(debugByteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
	        int textifiedCalleeOffset = mem.getInt(api.toAddr(debugByteCounter));
	        api.setPreComment(api.toAddr(debugByteCounter), "Textified Callee Offset: " + textifiedCalleeOffset);
	        debugByteCounter += 4;
	        
	        DataUtilities.createData(program, api.toAddr(debugByteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
	        int stringTableOffsetDebug = mem.getInt(api.toAddr(debugByteCounter));
	        api.setPreComment(api.toAddr(debugByteCounter), "String Table Offset: " + stringTableOffsetDebug);
	        debugByteCounter += 4;
	        
	        DataUtilities.createData(program, api.toAddr(debugByteCounter), new UnsignedIntegerDataType(), -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
	        int debugDataSize = mem.getInt(api.toAddr(debugByteCounter));
	        api.setPreComment(api.toAddr(debugByteCounter), "Debug Data Size: " + debugDataSize);
	        debugByteCounter += 4;
			
					
			//byteCounter = debugInfoOffset + 7 * 4;

			if (filenameCount > 0)
			{
				mem.createInitializedBlock("Debug Filename Table", api.toAddr(debugByteCounter), inputStreamForMem, filenameCount * 8, monitor, false);
				debugInfoViewFolder.reparent("Debug Filename Table", root);

				for (int i = 0; i < filenameCount; i++) {
					int entryOffset = debugByteCounter + (i * 8); // Each entry is 8 bytes

					StructureDataType struct = new StructureDataType("Filename Table Entry", 0);

					DataType uint32 = new UnsignedIntegerDataType();
					struct.add(uint32, "offset", "Offset of the filename");
					struct.add(uint32, "length", "Length of the filename");
					api.createData(api.toAddr(entryOffset), struct);
					
					//StructureDataType functionSourceTableEntryStruct = HermesFunctionSourceStruct.createFunctionSourceTableEntryStruct();
					//DataUtilities.createData(program, api.toAddr(entryOffset), functionSourceTableEntryStruct, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
					api.setPreComment(api.toAddr(entryOffset), "Filename Table Entry " + i);					
				}

				debugByteCounter += filenameCount * 8;
			}

			int debugStringStorageSize = filenameStorageSize;

			if (debugStringStorageSize > 0)
			{
				mem.createInitializedBlock("Debug String Storage", api.toAddr(debugByteCounter), inputStreamForMem, debugStringStorageSize, monitor, false);
				debugInfoViewFolder.reparent("Debug String Storage", root);
				DataUtilities.createData(program, api.toAddr(debugByteCounter), new StringDataType(), debugStringStorageSize, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);

				debugByteCounter += debugStringStorageSize;
			}

			if (fileRegionCount > 0)
			{
				mem.createInitializedBlock("Debug File Region Table", api.toAddr(debugByteCounter), inputStreamForMem, fileRegionCount * 12, monitor, false);
				debugInfoViewFolder.reparent("Debug File Region Table", root);

				for (int i = 0; i < fileRegionCount; i++) {
					int entryOffset = debugByteCounter + (i * 12); // Each entry is 12 bytes

					StructureDataType struct = new StructureDataType("File Region Table Entry", 0);

					DataType uint32 = new UnsignedIntegerDataType();
					struct.add(uint32, "from_address", "From Address");
					struct.add(uint32, "filename_id", "Filename ID");
					struct.add(uint32, "source_mapping_url_id", "Source Mapping URL ID");

					api.createData(api.toAddr(entryOffset), struct);

					//StructureDataType functionSourceTableEntryStruct = HermesFunctionSourceStruct.createFunctionSourceTableEntryStruct();
					//DataUtilities.createData(program, api.toAddr(entryOffset), functionSourceTableEntryStruct, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
					api.setPreComment(api.toAddr(entryOffset), "File Region Table Entry " + i);
				}

				debugByteCounter += fileRegionCount * 12;
			}

			int sourcesDataStorageSize = scopeDescDataOffset;

			if (sourcesDataStorageSize > 0) {
				MemoryBlock sourcesData = mem.createInitializedBlock("Sources Data", api.toAddr(debugByteCounter), inputStreamForMem, sourcesDataStorageSize, monitor, false);
				debugInfoViewFolder.reparent("Sources Data", root);

				byte[] bytes = new byte[sourcesDataStorageSize];
				sourcesData.getBytes(api.toAddr(debugByteCounter), bytes);
				HermesSourcesDataStruct.parse(bytes);


				debugByteCounter += sourcesDataStorageSize;
			}

			int scopeDescDataStorageSize = textifiedCalleeOffset - scopeDescDataOffset;

			if (scopeDescDataStorageSize > 0) {
				mem.createInitializedBlock("Scope Desc Data", api.toAddr(debugByteCounter), inputStreamForMem, scopeDescDataStorageSize, monitor, false);
				debugInfoViewFolder.reparent("Scope Desc Data", root);
				debugByteCounter += scopeDescDataStorageSize;
			}

			int textifiedCalleeStorageSize = stringTableOffsetDebug - textifiedCalleeOffset;

			if (textifiedCalleeStorageSize > 0) {
				mem.createInitializedBlock("Textified Callee Data", api.toAddr(debugByteCounter), inputStreamForMem, textifiedCalleeStorageSize, monitor, false);
				debugInfoViewFolder.reparent("Textified Callee Data", root);
				debugByteCounter += textifiedCalleeStorageSize;
			}

			int stringTableStorageSize = debugDataSize - stringTableOffsetDebug;

			if (stringTableStorageSize > 0) {
				mem.createInitializedBlock("DebugString Table", api.toAddr(debugByteCounter), inputStreamForMem, stringTableStorageSize, monitor, false);
				debugInfoViewFolder.reparent("DebugString Table", root);
				debugByteCounter += stringTableStorageSize;
			}

			mem.createInitializedBlock("Footer", api.toAddr(debugByteCounter), inputStreamForMem, 20, monitor, false);

			// Create footer struct
			StructureDataType struct = new StructureDataType("Footer Entry", 0);
			
			DataType arr_dt = new ArrayDataType(ByteDataType.dataType, 20, 1);
			struct.add(arr_dt, "sha1_hash", "SHA1 hash of the file");
			api.createData(api.toAddr(debugByteCounter), struct);

			debugByteCounter += 20; // length of the sha1 footer

			if (debugByteCounter != length) {
				throw new RuntimeException("Error: did not reach end of file. Stopped at " + debugByteCounter + " but file length is " + length);
			}


			monitor.setMessage( "Hermes Loader: Create Functions" );
			// handle functions
			for (FunctionInfo functionInfo : bytecodeFile.functions) {
				if (functionInfo.funcHeader == null) {
					createFunctionFromHeader(program, api, mem, stringTableOffset, stringStorageBase, overflowStringTableBase, functionInfo.smallFuncHeader);
				} else {
					createFunctionFromHeader(program, api, mem, stringTableOffset, stringStorageBase, overflowStringTableBase, functionInfo.funcHeader);
				}				
			}			
			
			// handle strings
		    HermesStringUtil.createHermesStringBlock(program, api, mem, monitor, bytecodeFile.allStrings);

			ProgramModule customHelperSpace = root.createModule("Custom Helper Space");
			// populate a new stringData space			
			AddressSpace stringData = program.getAddressFactory().getDefaultAddressSpace();
			if (stringData == null) {
				throw new RuntimeException("Language is missing stringData space (type=ram_space) in SLEIGH");
			}
			

			Address stringDataAddr = stringData.getAddress(OFFSET_STRING_DATA);  // where in stringData to place it
			ByteArrayOutputStream joined = new ByteArrayOutputStream();
			for (HbcString str : bytecodeFile.allStrings) {
				if(str.isUTF16) {
					// Convert to UTF-16LE bytes and then back to a String
					byte[] utf16Bytes = str.value.getBytes(StandardCharsets.UTF_16LE);
					joined.write(utf16Bytes);
					joined.write(0); // null terminator	
					joined.write(0); // null terminator	
				} else {
					byte[] utf8Bytes = str.value.getBytes(StandardCharsets.UTF_8);
					joined.write(utf8Bytes);
					joined.write(0); // null terminator
				}
							
			}
			InputStream in = new ByteArrayInputStream(joined.toByteArray());

			mem.createInitializedBlock("String Data", stringDataAddr, in, joined.size(), monitor, false);
			customHelperSpace.reparent("String Data", root);

			Address addr_writer = stringDataAddr;
			for (HbcString string : bytecodeFile.allStrings) {
				
				int stringLength;
				if(string.isUTF16) {
					stringLength = string.length * 2;
					stringLength += 2; // account for two null bytes
					DataUtilities.createData(program, addr_writer, new UnicodeDataType(), stringLength, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
				} else {
					stringLength = string.length;
					stringLength += 1; // account for null byte
					DataUtilities.createData(program, addr_writer, new StringDataType(), stringLength, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
				}
				
				addr_writer = addr_writer.add(stringLength);
			}

			// create new string table
			// contains all strings, overflow and normal
			// offset to stringData
			// isUtf16
			// length

			// populate a new stringTable space
			AddressSpace stringTable = program.getAddressFactory().getDefaultAddressSpace();
			if (stringTable == null) {
				throw new RuntimeException("Language is missing stringTable space (type=ram_space) in SLEIGH");
			}
			
			ReferenceManager rm = program.getReferenceManager();

			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			Address stringTableAddr = stringTable.getAddress(OFFSET_STRING_TABLE);
			Address stringTableAddrWriter = stringTableAddr;
			for (HbcString str : bytecodeFile.allStrings) {
				
				int offset = (int)stringDataAddr.getOffset();
				byte[] offsetByte = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(offset).array();
				byte[] lengthByte = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(str.length).array();
				
				outputStream.write(offsetByte);
				outputStream.write(str.isUTF16 ? 1 : 0); // isUTF16 flag
				outputStream.write(lengthByte);

				Reference reference = rm.addMemoryReference(stringTableAddrWriter, stringDataAddr, RefType.DATA, SourceType.USER_DEFINED, 0);
				rm.setPrimary(reference, true);

				stringTableAddrWriter = stringTableAddrWriter.add(4 + 1 + 4);
				stringDataAddr = stringDataAddr.add(str.isUTF16 ? (str.length * 2) + 2 : str.length + 1);
			}
			InputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());

			mem.createInitializedBlock("String Table", stringTableAddr, inputStream, outputStream.size(), monitor, false);
			customHelperSpace.reparent("String Table", root);

			StructureDataType loadedStringTableEntryStructUTF16 = createLoadedStringTableEntryStruct(true);
			StructureDataType loadedStringTableEntryStructUTF8 = createLoadedStringTableEntryStruct(false);

			int loadedStringIndex = 0;
			for (HbcString str : bytecodeFile.allStrings) {
				if(str.isUTF16) {
					api.createData(stringTableAddr, loadedStringTableEntryStructUTF16);
				} else {
					api.createData(stringTableAddr, loadedStringTableEntryStructUTF8);
				}

				// Add a numbered pre-comment at the table entry address
				String comment = String.format("Loaded String %d: isUTF16=%b length=%d", loadedStringIndex, str.isUTF16, str.length);
				api.setPreComment(stringTableAddr, comment);

				stringTableAddr = stringTableAddr.add(4 + 1 + 4);
				loadedStringIndex++;
			}


			// create loadedFunctionTable
			AddressSpace loadedFunctionTable = program.getAddressFactory().getDefaultAddressSpace();
			if (loadedFunctionTable == null) {
				throw new RuntimeException("Language is missing loadedFunctionTable space (type=ram_space) in SLEIGH");
			}

			ByteArrayOutputStream functionOutputStream = new ByteArrayOutputStream();
			Address loadedFunctionTableAddr = loadedFunctionTable.getAddress(OFFSET_FUNCTION_TABLE);

			for (FunctionInfo fiTmp : bytecodeFile.functions) {
				int offTmp = (fiTmp.funcHeader == null) ? fiTmp.smallFuncHeader.offset : fiTmp.funcHeader.offset;
				int paramTmp = (fiTmp.funcHeader == null) ? fiTmp.smallFuncHeader.paramCount : fiTmp.funcHeader.paramCount;
				functionOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(offTmp).array());
				functionOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(paramTmp).array());
			}

			InputStream functionInputStream = new ByteArrayInputStream(functionOutputStream.toByteArray());

			mem.createInitializedBlock("Loaded Function Table", loadedFunctionTableAddr, functionInputStream, functionOutputStream.size(), monitor, false);
			customHelperSpace.reparent("Loaded Function Table", root);

			Address loadedFunctionTableAddrWriter = loadedFunctionTableAddr;
			int loadedFuncIndex = 0;
			for (FunctionInfo functionInfo : bytecodeFile.functions) {
				// Create the data structure for the loaded function table entry
				api.createData(loadedFunctionTableAddrWriter, createLoadedFunctionTableEntryStruct());

				// Determine header fields (small or normal)
				int funcOffset = (functionInfo.funcHeader == null) ? functionInfo.smallFuncHeader.offset : functionInfo.funcHeader.offset;
				int paramCount = (functionInfo.funcHeader == null) ? functionInfo.smallFuncHeader.paramCount : functionInfo.funcHeader.paramCount;
				int functionNameIndex = (functionInfo.funcHeader == null) ? functionInfo.smallFuncHeader.functionName : functionInfo.funcHeader.functionName;

				String funcName = HermesStringTableUtil.getNthStringFromStringStorage(program, mem, stringTableOffset, stringStorageBase, overflowStringTableBase, functionNameIndex);

				// Add a numbered pre-comment at the table entry address
				String comment = String.format("Loaded Function %d: name='%s' offset=0x%X paramCount=%d", loadedFuncIndex, funcName, funcOffset, paramCount);
				api.setPreComment(loadedFunctionTableAddrWriter, comment);

				// Advance to next entry (each is 8 bytes: 4 offset + 4 paramCount)
				loadedFunctionTableAddrWriter = loadedFunctionTableAddrWriter.add(4 + 4);
				loadedFuncIndex++;
			}


			monitor.setMessage( "Hermes Loader: Done" );
		} catch (Exception e) {
			Msg.debug(this, "Hermes Loader: Error");
			log.appendException( e );
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		return super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout);
	}

	/**
	 * Creates a function from a function header
	 */
	private void createFunctionFromHeader(Program program, FlatProgramAPI api, Memory mem, int stringTableOffset, int stringStorageBase, int overflowStringTableBase, HbcBinaryStructs.FunctionInfoBase funcHeader) {
		try {
			String functionNameString = HermesStringTableUtil.getNthStringFromStringStorage(program, mem, stringTableOffset, stringStorageBase, overflowStringTableBase, funcHeader.functionName);
			
			// Sanitize function name for Ghidra
			String sanitizedName = functionNameString.replace(" ", "\u00A0");
			sanitizedName = SymbolUtilities.replaceInvalidChars(sanitizedName, true);			
			
			int maxLen = SymbolUtilities.MAX_SYMBOL_NAME_LENGTH - 16;
			if (sanitizedName.length() > maxLen) {
				sanitizedName = sanitizedName.substring(0, maxLen);
			}

			Address functionAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(funcHeader.offset);
			int functionLength = funcHeader.bytecodeSizeInBytes;
			Address functionEnd = functionAddress.add(functionLength -1);

			// set function with name global as entry point
			if(sanitizedName.equals("global")) {
				api.addEntryPoint(functionAddress);
			}
			// Check if function already exists at this address before creating
			if (program.getFunctionManager().getFunctionAt(functionAddress) == null) {
				program.getFunctionManager().createFunction(sanitizedName, functionAddress, new AddressSet(functionAddress, functionEnd), SourceType.ANALYSIS);
			} else {
				// check if function is the same, if only the name is different, add a label with the new name, except its empty
				Function existingFunction = program.getFunctionManager().getFunctionAt(functionAddress);
				if(!existingFunction.getName().equals(sanitizedName) && !sanitizedName.isEmpty()) {
					SymbolTable symbolTable = program.getSymbolTable();
					symbolTable.createLabel(functionAddress, sanitizedName, SourceType.ANALYSIS);
				}

				// If the existing function is not the same as the new function, throw an exception
				if (!existingFunction.getBody().equals(new AddressSet(functionAddress, functionEnd))) {
					throw new RuntimeException("Function at " + functionAddress + " is already defined with a different body");
				}
			}
		} catch (InvalidInputException | OverlappingFunctionException | CancelledException e) {
			Msg.debug(this, "Error creating function from header: " + e.getMessage());
			throw new RuntimeException("Error creating function from header: " + e.getMessage());
		}
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
