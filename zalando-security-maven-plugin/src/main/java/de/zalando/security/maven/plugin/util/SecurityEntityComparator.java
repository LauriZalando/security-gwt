package de.zalando.security.maven.plugin.util;

import java.util.Comparator;

import de.zalando.security.maven.plugin.domain.SecurityEntity;

/**
 * @author  skunz
 */
public class SecurityEntityComparator implements Comparator<SecurityEntity> {

    @Override
    public int compare(final SecurityEntity o1, final SecurityEntity o2) {
        return Boolean.valueOf(o1.getSecurityResult().isSecure()).compareTo(Boolean.valueOf(
                    o2.getSecurityResult().isSecure()));
    }
}
