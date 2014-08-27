# Zalando Security Maven Plugin
This plugin can be used to get adhoc analyzation about security goals.

## Usage for GWT RPC security analyzation (based on Spring Security)

Configure the plugin within your project

## Configuration

#### Plugin Configuration in pom.xml 

There are 2 configurations that need to be set to get the plugin running

    servicePattern: Basically this is related to the servicePattern of gwt-maven-plugin to find all RPC Services
 
    analyzePattern: Because of GWT the RPC Service needs to implementations to be secured. Controller that triggers the security-proxy call to the Implementation. Those pattern defines the search filter for those implementations.

Pattern can cover all Files (**/*) but this may take longer in analyze because the analysis itself is done using reflection.

Example:

    <plugin>
      <groupId>de.zalando.security</groupId>
      <artifactId>zalando-security-maven-plugin</artifactId>
      <version>1.0.0</version>
      <configuration>
        <servicePattern>
          <param>de/zalando/zalos/**/client/service/*Service.java</param>
        </servicePattern>
        <analyzePattern>
          <param>de/zalando/zalos/**/server/**/*Controller*.java</param>
          <param>de/zalando/zalos/**/server/**/*Impl*.java</param>
        </analyzePattern>
      </configuration>
    </plugin>

### Optional parameter for analysis

For analysis you can define a simple summary or a detailed output of the result. Therefor you can use the parameter

    (deprecated) analyze.detailed=true/false

    analyze.output=SIMPLE|DETAILED|PRETTY
 
    SIMPLE prints as less information as possible (only overall result summary)

    DETAILED prints a list of all services and their coverage

    PRETTY prints a list of all unsecured methods

### Execution

    mvn zalando-security:gwt-analyze
    mvn zalando-security:gwt-analyze -Danalyze.output=DETAILED
