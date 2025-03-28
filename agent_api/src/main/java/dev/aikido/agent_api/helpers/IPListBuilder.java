package dev.aikido.agent_api.helpers;

import dev.aikido.agent_api.helpers.net.IPList;

import java.util.Collection;
import java.util.Collections;

public final class IPListBuilder {
    private IPListBuilder() {}

    public static IPList createIPList(Collection<String> ips) {
        if (ips == null) {
            return new IPList(Collections.emptyList());
        }
        return new IPList(ips);
    }
}
