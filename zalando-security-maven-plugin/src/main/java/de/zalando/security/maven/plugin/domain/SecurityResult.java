package de.zalando.security.maven.plugin.domain;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * @author  skunz
 */
public final class SecurityResult {

    private final String reference;

    private final boolean secure;
    private final Map<Boolean, Set<String>> securities;

    public SecurityResult(final String reference, final Map<Boolean, Set<String>> securities) {
        this.reference = reference;

        if (securities == null || securities.isEmpty()) {
            this.securities = new HashMap<>();
            this.securities.put(Boolean.TRUE, new HashSet<String>());
            this.securities.put(Boolean.FALSE, new HashSet<String>());
        } else {
            this.securities = securities;
        }

        secure = getUnsecuredMethodCount() == 0 && getSecuredMethodCount() > 0;
    }

    public boolean isSecure() {
        return secure;
    }

    public Set<String> getUnsecuredMethods() {
        return this.securities.get(Boolean.FALSE);
    }

    public int getSecuredMethodCount() {
        return this.securities.get(Boolean.TRUE).size();
    }

    public int getUnsecuredMethodCount() {
        return this.securities.get(Boolean.FALSE).size();
    }

    public double getSecurityRatio() {
        if (getMethodCount() == 0) {
            return 0.0d;
        }

        return getSecuredMethodCount() * 100.0d / getMethodCount();
    }

    public int getMethodCount() {
        return getSecuredMethodCount() + getUnsecuredMethodCount();
    }

    public String getReference() {
        return reference;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 97 * hash + Objects.hashCode(this.reference);
        hash = 97 * hash + (this.secure ? 1 : 0);
        hash = 97 * hash + Objects.hashCode(this.securities);
        return hash;
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj == null) {
            return false;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }

        final SecurityResult other = (SecurityResult) obj;
        if (!Objects.equals(this.reference, other.reference)) {
            return false;
        }

        if (this.secure != other.secure) {
            return false;
        }

        if (!Objects.equals(this.securities, other.securities)) {
            return false;
        }

        return true;
    }

}
