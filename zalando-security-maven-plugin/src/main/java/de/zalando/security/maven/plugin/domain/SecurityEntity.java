package de.zalando.security.maven.plugin.domain;

import java.lang.reflect.Method;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.security.access.prepost.PreAuthorize;

import org.springframework.stereotype.Component;

import de.zalando.security.maven.plugin.util.AnalyzeHelper;

/**
 * @author  skunz
 */
public class SecurityEntity {

    private final String name;
    private String implName;

    private final Map<Boolean, Set<String>> methodSecurity;

    private int implCount;
    private List<String> interfaceMethods;

    public SecurityEntity(final Class interfaceClass) {
        name = interfaceClass.getPackage().getName() + "." + interfaceClass.getSimpleName();

        interfaceMethods = new ArrayList<>();
        for (Method method : interfaceClass.getMethods()) {
            String identifier = AnalyzeHelper.buildIdentifier(method);
            interfaceMethods.add(identifier);
        }

        methodSecurity = new HashMap<>();
        methodSecurity.put(Boolean.TRUE, new HashSet<String>());
        methodSecurity.put(Boolean.FALSE, new HashSet<String>());
    }

    /**
     * Analyzes the given service implementations against its interface.
     *
     * @param  serviceImplementations
     */
    public void analyze(final List<Class> serviceImplementations) {
        boolean classSecured;
        for (Class implementation : serviceImplementations) {
            implCount++;

            classSecured = false;

            if (!implementation.isAnnotationPresent(Component.class)) {

                // only fill up methods for the service implementation, not the controller
                continue;
            }

            implName = implementation.getSimpleName();

            if (implementation.isAnnotationPresent(PreAuthorize.class)) {
                classSecured = true;
            }

            for (Method method : implementation.getMethods()) {
                String methodName = AnalyzeHelper.buildIdentifier(method);
                if (!interfaceMethods.contains(methodName)) {
                    continue;
                }

                if (classSecured) {
                    methodSecurity.get(Boolean.TRUE).add(methodName);
                    continue;
                }

                if (method.isAnnotationPresent(PreAuthorize.class)) {
                    methodSecurity.get(Boolean.TRUE).add(methodName);
                    continue;
                }

                methodSecurity.get(Boolean.FALSE).add(methodName);
            }
        }
    }

    public SecurityResult getSecurityResult() {
        SecurityResult result;
        if (implCount != 2) {
            Map<Boolean, Set<String>> tmp = new HashMap<>();
            tmp.put(Boolean.FALSE, new HashSet<>(interfaceMethods));
            tmp.put(Boolean.TRUE, new HashSet<String>());
            result = new SecurityResult(implName, tmp);
        } else {
            result = new SecurityResult(implName, methodSecurity);
        }

        return result;
    }

    public String getName() {
        return name;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 43 * hash + Objects.hashCode(this.name);
        hash = 43 * hash + Objects.hashCode(this.methodSecurity);
        hash = 43 * hash + this.implCount;
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

        final SecurityEntity other = (SecurityEntity) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }

        if (!Objects.equals(this.methodSecurity, other.methodSecurity)) {
            return false;
        }

        if (this.implCount != other.implCount) {
            return false;
        }

        return true;
    }

}
