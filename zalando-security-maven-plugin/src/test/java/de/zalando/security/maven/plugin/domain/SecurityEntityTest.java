/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.zalando.security.maven.plugin.domain;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import org.springframework.security.access.prepost.PreAuthorize;

import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;

import com.google.gwt.user.client.rpc.RemoteService;

/**
 * @author  skunz
 */
public class SecurityEntityTest {

    @Test
    public void test() {

        // unsecured
        List<Class> impls = new ArrayList<>();
        impls.add(MyServiceController.class);
        impls.add(MyServiceImpl.class);

        SecurityResult securityResult = prepare(MyService.class, impls);
        Assert.assertFalse(securityResult.isSecure());
        Assert.assertEquals(0, (int) securityResult.getSecurityRatio());
        // unsecured

        // half secured
        impls = new ArrayList<>();
        impls.add(MyHalfSecuredServiceController.class);
        impls.add(MyHalfSecuredServiceImpl.class);

        securityResult = prepare(MyHalfSecuredService.class, impls);
        Assert.assertFalse(securityResult.isSecure());
        Assert.assertEquals(50, (int) securityResult.getSecurityRatio());
        // half secured

        // fully secured class and method based
        impls = new ArrayList<>();
        impls.add(MySecured1ServiceController.class);
        impls.add(MySecured1ServiceImpl.class);

        securityResult = prepare(MySecured1Service.class, impls);
        Assert.assertTrue(securityResult.isSecure());
        Assert.assertEquals(100, (int) securityResult.getSecurityRatio());

        impls = new ArrayList<>();
        impls.add(MySecured2ServiceController.class);
        impls.add(MySecured2ServiceImpl.class);

        securityResult = prepare(MySecured2Service.class, impls);
        Assert.assertTrue(securityResult.isSecure());
        Assert.assertEquals(100, (int) securityResult.getSecurityRatio());
        // fully secured class and method based

        // unsecured, no controller
        impls = new ArrayList<>();
        impls.add(MySecured2ServiceImpl.class);

        securityResult = prepare(MySecured2Service.class, impls);
        Assert.assertFalse(securityResult.isSecure());
        Assert.assertEquals(0, (int) securityResult.getSecurityRatio());
        // unsecured, no controller
    }

    private SecurityResult prepare(final Class interfaze, final List<Class> impls) {
        SecurityEntity e = new SecurityEntity(interfaze);
        e.analyze(impls);
        return e.getSecurityResult();
    }

    interface MyService extends RemoteService {

        void method1();
    }

    @Controller
    class MyServiceController implements MyService {

        @Override
        public void method1() { }
    }

    @Component
    class MyServiceImpl implements MyService {

        @Override
        public void method1() { }
    }

    interface MyHalfSecuredService extends RemoteService {

        void method1();

        int method2(String a);
    }

    @Controller
    class MyHalfSecuredServiceController implements MyHalfSecuredService {

        @Override
        public void method1() { }

        @Override
        public int method2(final String a) {
            return 0;
        }
    }

    @Component
    class MyHalfSecuredServiceImpl implements MyHalfSecuredService {

        @Override
        public void method1() { }

        @Override
        @PreAuthorize("hasRole('')")
        public int method2(final String a) {
            return 0;
        }
    }

    interface MySecured1Service extends RemoteService {

        void method1();

    }

    @Controller
    class MySecured1ServiceController implements MySecured1Service {

        @Override
        public void method1() { }
    }

    @Component
    class MySecured1ServiceImpl implements MySecured1Service {

        @Override
        @PreAuthorize("hasRole('')")
        public void method1() { }
    }

    interface MySecured2Service extends RemoteService {

        void method1();

    }

    @Controller
    class MySecured2ServiceController implements MySecured2Service {

        @Override
        public void method1() { }
    }

    @Component
    @PreAuthorize("hasRole('')")
    class MySecured2ServiceImpl implements MySecured2Service {

        @Override
        public void method1() { }
    }
}
