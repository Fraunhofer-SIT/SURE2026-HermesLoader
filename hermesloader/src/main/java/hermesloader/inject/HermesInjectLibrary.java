package hermesloader.inject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.util.Msg;

public class HermesInjectLibrary extends PcodeInjectLibrary {
	private static final String LOG_PREFIX = "[HermesInjectLibrary] ";

    public HermesInjectLibrary(SleighLanguage lang) {
        super(lang);
    }

    @Override
    public InjectPayload allocateInject(String sourceName, String name, int tp) {
        Msg.debug(HermesInjectLibrary.class,
            LOG_PREFIX + "Allocating inject: " + sourceName + " " + name + " " + tp);
        if ("getByIdInject".equals(name)) {
            return new InjectPayloadHermesGetById(sourceName);
        }
        if ("newArrayWithBufferInject".equals(name)) {
            return new InjectPayloadHermesNewArrayWithBuffer(sourceName);
        }
        if ("newObjectWithBufferInject".equals(name)) {
            return new InjectPayloadHermesNewObjectWithBuffer(sourceName);
        }
        return super.allocateInject(sourceName, name, tp);
    }
}