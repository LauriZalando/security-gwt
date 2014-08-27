
package de.zalando.security.maven.plugin;

import java.io.File;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;

import org.codehaus.plexus.util.Scanner;

import org.sonatype.plexus.build.incremental.BuildContext;

import com.google.common.base.Predicate;
import com.google.common.collect.Lists;

import de.zalando.security.maven.plugin.domain.SecurityEntity;
import de.zalando.security.maven.plugin.util.AnalyzeHelper;
import de.zalando.security.maven.plugin.util.ResultLogger;

/**
 * @goal                          gwt-analyze
 * @requiresDependencyResolution  compile
 */
public class RpcSecurityAnalyzeMojo extends AbstractMojo {

    /**
     * @component
     */
    private BuildContext buildContext;

    /**
     * The maven project descriptor.
     *
     * @parameter  property="project"
     * @required
     * @readonly
     */
    private MavenProject project;

    /**
     * not used yet.
     */
    private boolean failOnError = false;

    /**
     * For detailed logging output.
     *
     * @parameter  property="analyze.detailed"
     */
    private boolean detailed = false;

    /**
     * Defines the outputMode. Possible values are
     *
     * <ul>
     *   <li>{@link OutputMode#SIMPLE} prints only overall result</li>
     *   <li>{@link OutputMode#DETAILED} prints summary for every service</li>
     *   <li>{@link OutputMode#PRETTY} prints complete results including list of unsecured methods</li>
     * </ul>
     *
     * @parameter  property="analyze.output"
     */
    private OutputMode outputMode = null;

    /**
     * Basically this matches the defined service pattern of the project to be analyzed. This one could be extracted
     * from gwt-maven-plugin configuration
     *
     * @parameter
     * @required
     * @readonly
     */
    private String[] servicePattern;

    /**
     * In case CGLIB aspects aren't activated the project needs a ServiceController and a ServiceImpl that implement the
     * RemoteService interface. We want to look out for them
     *
     * @parameter
     * @required
     * @readonly
     */
    private String[] analyzePattern;

    private final ClasspathBuilder classpathBuilder = new ClasspathBuilder();

    private ClassLoader classLoader;

    @Override
    public void execute() throws MojoExecutionException {

        this.classLoader = getProjectClassLoader();

        final List<Class> serviceInterfaces = Lists.newArrayList();
        final List<SecurityEntity> securityEntities = Lists.newArrayList();

        final List<String> sourceRoots = project.getCompileSourceRoots();

        for (String sourceRoot : sourceRoots) {
            try {
                serviceInterfaces.addAll(getClasses(sourceRoot, servicePattern, new Predicate<Class>() {

                            @Override
                            public boolean apply(final Class clazz) {
                                return clazz.isInterface();
                            }
                        }));
            } catch (Throwable e) {
                getLog().error("Failed to collect service interfaces", e);
                if (failOnError) {
                    throw new MojoExecutionException("Failed to analyze RPC interfaces", e);
                }
            }
        }

        SecurityEntity entity;
        for (final Class serviceInterface : serviceInterfaces) {
            for (String sourceRoot : sourceRoots) {
                try {
                    entity = new SecurityEntity(serviceInterface);
                    securityEntities.add(entity);

                    entity.analyze(getClasses(sourceRoot, analyzePattern, new Predicate<Class>() {

                                @Override
                                public boolean apply(final Class clazz) {
                                    return serviceInterface.isAssignableFrom(clazz);
                                }
                            }));

                } catch (Throwable e) {
                    getLog().error("Failed to collect implementations for service interface", e);
                    if (failOnError) {
                        throw new MojoExecutionException("Failed to analyze RPC interfaces", e);
                    }
                }
            }
        }

        final ResultLogger logger = new ResultLogger(getLog());
        logger.logResults(securityEntities, getOutputMode());
    }

    private List<Class> getClasses(final String sourceRoot, final String[] includes, final Predicate<Class> predicate)
        throws Exception {

        final Scanner scanner = buildContext.newScanner(new File(sourceRoot));
        scanner.setIncludes(includes);
        scanner.scan();

        String[] sources = scanner.getIncludedFiles();
        if (sources.length == 0) {
            return new ArrayList<>();
        }

        List<Class> result = new ArrayList<>();
        for (String source : sources) {
            String className = AnalyzeHelper.getTopLevelClassName(source);

            Class clazz = Class.forName(className, false, classLoader);

            if (predicate.apply(clazz)) {
                result.add(clazz);
            }
        }

        return result;
    }

    private ClassLoader getProjectClassLoader() throws MojoExecutionException {
        Collection<File> classpath = getClasspath(Artifact.SCOPE_COMPILE);
        URL[] urls = new URL[classpath.size()];
        try {
            int i = 0;
            for (File classpathFile : classpath) {
                urls[i] = classpathFile.toURI().toURL();
                i++;
            }
        } catch (MalformedURLException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }

        return new URLClassLoader(urls, getClass().getClassLoader());
    }

    public Collection<File> getClasspath(final String scope) throws MojoExecutionException {
        try {
            Collection<File> files = classpathBuilder.buildClasspathList(project, scope, project.getArtifacts());
            if (getLog().isDebugEnabled()) {
                getLog().debug("RPC Securty execution classpath :");
                for (File f : files) {
                    getLog().debug(" " + f.getAbsolutePath());
                }
            }

            return files;
        } catch (Exception e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }
    }

    private OutputMode getOutputMode() {
        if (outputMode == null) {
            if (detailed) {
                return OutputMode.PRETTY;
            } else {
                return OutputMode.DETAILED;
            }
        }

        return outputMode;
    }

    public enum OutputMode {
        SIMPLE,
        DETAILED,
        PRETTY
    }
}
