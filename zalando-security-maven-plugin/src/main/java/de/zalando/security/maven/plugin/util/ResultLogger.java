/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.zalando.security.maven.plugin.util;

import java.util.Collections;
import java.util.List;

import org.apache.maven.plugin.logging.Log;

import de.zalando.security.maven.plugin.RpcSecurityAnalyzeMojo.OutputMode;
import de.zalando.security.maven.plugin.domain.SecurityEntity;
import de.zalando.security.maven.plugin.domain.SecurityResult;

/**
 * @author  skunz
 */
public class ResultLogger {

    private final Log logger;

    public ResultLogger(final Log logger) {
        this.logger = logger;
    }

    public void logResults(final List<SecurityEntity> securityEntities, final OutputMode outputMode) {
        if (!logger.isInfoEnabled()) {
            return;
        }

        int methodCount = 0;
        int secured = 0;

        Collections.sort(securityEntities, new SecurityEntityComparator());

        StringBuilder sb = new StringBuilder();

        for (SecurityEntity entity : securityEntities) {
            SecurityResult result = entity.getSecurityResult();

            methodCount += result.getMethodCount();
            secured += result.getSecuredMethodCount();

            if (outputMode != OutputMode.SIMPLE) {
                sb.append(String.format("Entity is secure [%s]: [%s]", result.isSecure(), entity.getName()));
                if (!result.isSecure()) {
                    sb.append(String.format(" (%s)", result.getSecurityRatio()));
                }

                sb.append("\n");
            }

            if (outputMode == OutputMode.PRETTY) {
                sb.append(String.format(" Method count [%s], Secured [%s], Unsecured [%s]", result.getMethodCount(),
                        result.getSecuredMethodCount(), result.getUnsecuredMethodCount()));
                sb.append("\n");
                sb.append(String.format(" Ratio [%s]", result.getSecurityRatio()));
                sb.append("\n");

                if (!result.isSecure()) {
                    sb.append(" Unsecured Method-List:");
                    sb.append("\n");

                    for (String unsecuredMethod : result.getUnsecuredMethods()) {
                        sb.append(String.format(" - %s", unsecuredMethod));
                        sb.append("\n");
                    }
                }

                sb.append("\n");
            }
        }

        if (outputMode != OutputMode.SIMPLE) {
            sb.append("\n");
        }

        if (methodCount == 0) {
            sb.append("RESULT: no methods = nothing to secure");
        } else {
            sb.append(String.format("RESULT: overall ratio = %s", (secured * 100.0d / methodCount)));
        }

        logger.info(sb.toString());
    }
}
