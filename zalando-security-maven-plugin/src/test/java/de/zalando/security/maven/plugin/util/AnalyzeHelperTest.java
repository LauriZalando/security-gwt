/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.zalando.security.maven.plugin.util;

import java.io.IOException;

import java.lang.reflect.Method;

import java.util.Arrays;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import org.springframework.security.access.prepost.PreAuthorize;

import org.springframework.stereotype.Component;

/**
 * @author  skunz
 */
public class AnalyzeHelperTest {

    @Test
    public void testBuildIdentifier() {

        List<String> methods = Arrays.asList("void method1()", "String method2(String, int)", "List method3(int)",
                "List method3(int, boolean)");

        for (Method m : TestInterface.class.getMethods()) {
            if (!methods.contains(AnalyzeHelper.buildIdentifier(m))) {
                Assert.fail("Method is not expected");
            }
        }
    }

    @Test
    public void testGetTopLevelClassName() {
        String fileName = "de/zalando/security/maven/plugin/domain/Entity.java";
        String result = AnalyzeHelper.getTopLevelClassName(fileName);

        Assert.assertTrue("de.zalando.security.maven.plugin.domain.Entity".equals(result));
    }

    interface TestInterface {

        void method1();

        String method2(String a, int b) throws IOException;

        List<Integer> method3(int a);

        List<Integer> method3(int a, boolean b);
    }

    @Component
    class ComponentClass { }

    @PreAuthorize("hasRole('')")
    class SecuredClass { }

    class PartlySecuredClass {

        public void method1() {
            return;
        }

        @PreAuthorize("hasRole('')")
        public int securedMethod1() {
            return 0;
        }
    }
}
