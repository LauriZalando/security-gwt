package de.zalando.security.maven.plugin.util;

import java.io.File;

import java.lang.reflect.Method;

/**
 * @author  skunz
 */
public final class AnalyzeHelper {

    private AnalyzeHelper() { }

    /**
     * Building a summary for the method signature.
     *
     * @param   method
     *
     * @return
     */
    public static String buildIdentifier(final Method method) {
        StringBuilder sb = new StringBuilder();

        sb.append(method.getReturnType().getSimpleName());
        sb.append(" ");
        sb.append(method.getName());
        sb.append("(");

        boolean first = true;
        for (Class parameter : method.getParameterTypes()) {
            if (!first) {
                sb.append(", ");
            }

            first = false;
            sb.append(parameter.getSimpleName());
        }

        sb.append(")");

        return sb.toString();
    }

    /**
     * Extract top level class name cutting ".java" from the end.
     *
     * @param   sourceFile
     *
     * @return
     */
    public static String getTopLevelClassName(final String sourceFile) {
        String className = sourceFile.substring(0, sourceFile.length() - 5); // strip ".java"
        return className.replace(File.separatorChar, '.');
    }
}
