package de.zalando.security.sanitizer;

import org.junit.Assert;
import org.junit.Test;

import com.google.gwt.safehtml.shared.SafeHtml;

import de.zalanod.security.sanitizer.SimpleHtmlSanitizerCopy;

/**
 * NOTE: SimpleHtmlSanitizer should be a copy of the code located in src/main/resources which is intended to replace the
 * original file
 */
public class SimpleHtmlSanitizerTest {

    private String sanitize(final String html) {
        final SafeHtml safe = SimpleHtmlSanitizerCopy.sanitizeHtml(html);
        return safe.asString();
    }

    private void testForEqualOutput(final String in) {
        final String sanitized = sanitize(in);
        Assert.assertEquals(in, sanitized);
    }

    private void testForDifferingOutput(final String in, final String expectedOut) {
        final String sanitized = sanitize(in);
        Assert.assertEquals(expectedOut, sanitized);
    }

    @Test
    public void testPlainText() {
        testForEqualOutput("I am not really special");
    }

    @Test
    public void testBr() throws Exception {
        testForEqualOutput("lalala <br/> blblb");
    }

    @Test
    public void testUsualTagging() throws Exception {
        testForEqualOutput("<p> Hello <br/> World! <b> All your base are belong to us. </b> <br/> another line</p>");
    }

    @Test
    public void testUsualStyling() throws Exception {
        testForEqualOutput("<p  style='text-align:center; ' readonly> Hello </p>");
    }

    @Test
    public void testUsualStylingWithMultipleCssStyleAttributes() throws Exception {
        testForEqualOutput("<p  style='text-align:center; font-size:123px; ' readonly> Hello </p>");
    }

    @Test
    public void testInvalidCssStyleEntry() throws Exception {
        testForDifferingOutput("<p style='text-align:center; DoesNotExist:123px'> Hello </p>",
            "&lt;p style=&#39;text-align:center; DoesNotExist:123px&#39;&gt; Hello &lt;/p&gt;");
    }

    @Test
    public void testOneOkOneNonOkTag() {

        testForDifferingOutput("<p style='text-align:center; DoesNotExist:123px'> Hello </p> <p> second try </p>",
            "&lt;p style=&#39;text-align:center; DoesNotExist:123px&#39;&gt; Hello &lt;/p&gt; <p> second try </p>");
    }

    @Test
    public void testRestrictedElementAttributes() {
        testForEqualOutput("<img  src='none'/>");
    }

    @Test
    public void testSimpleMaliciousInput() {
        testForDifferingOutput("<img src='none' onerror='alert(1)'/>",
            "&lt;img src=&#39;none&#39; onerror=&#39;alert(1)&#39;/&gt;");
    }

    @Test
    public void testInvalidHtmlElement() throws Exception {
        testForDifferingOutput("<1h>wrong header</1h>", "&lt;1h&gt;wrong header&lt;/1h&gt;");
    }

    @Test
    public void testInvalidStyleEntry() throws Exception {
        testForDifferingOutput("<p style='this_will_not_work:'>wrong</p>",
            "&lt;p style=&#39;this_will_not_work:&#39;&gt;wrong&lt;/p&gt;");
    }

    @Test
    public void testGloballyAllowedAttributes() throws Exception {
        testForEqualOutput("<p  id='noproblem'> Hello </p>");
        testForEqualOutput("<p  lang='noproblem'> Hello </p>");
    }

    @Test
    public void testPossibleStyleExploit() throws Exception {
        testForDifferingOutput("<p style='text-align:center;' justsomething> Hello </p>",
            "&lt;p style=&#39;text-align:center;&#39; justsomething&gt; Hello &lt;/p&gt;");
    }

    @Test
    public void testNbsp() {
        testForEqualOutput("&nbsp;");
        testForEqualOutput("<b>&nbsp;test</b>");
        testForEqualOutput("&nbsp;<b>test</b>");
    }

    @Test
    public void testAttributeValueEscaping() {
        testForDifferingOutput("<img id='alert(1)'/>", "<img  id='alert&#x28;1&#x29;'/>");
    }

    @Test
    public void testProblemInTimeRegistration() {
        testForEqualOutput(
            "<h3><p>Zeiterfassung konnte nicht durchgeführt werden!<br/> BITTE DER IT MELDEN!</p><p><br/><strong>Fehler:</strong> Der Nutzer mit dem Barcode 234234 konnte nicht gefunden werden.</p></h3>");
    }

    @Test
    public void testMaliciousDiv() {
        testForDifferingOutput("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
            "&lt;DIV STYLE=&quot;background-image: url(javascript:alert(&#39;XSS&#39;))&quot;&gt;");
    }

    @Test
    public void testScriptTag() {
        testForDifferingOutput("<script>var currentValue='UNTRUSTED DATA';</script>",
            "&lt;script&gt;var currentValue=&#39;UNTRUSTED DATA&#39;;&lt;/script&gt;");

        testForDifferingOutput("<script>someFunction('UNTRUSTED DATA');</script>",
            "&lt;script&gt;someFunction(&#39;UNTRUSTED DATA&#39;);&lt;/script&gt;");

        testForDifferingOutput("<script>document.write(\"UNTRUSTED INPUT: \" + document.location.hash);<script/>",
            "&lt;script&gt;document.write(&quot;UNTRUSTED INPUT: &quot; + document.location.hash);&lt;script/&gt;");
    }

    @Test
    public void testNested() {
        testForDifferingOutput("<span> <img src='none' onerror='alert(1)'/> </span>",
            "<span> &lt;img src=&#39;none&#39; onerror=&#39;alert(1)&#39;/&gt; </span>");
    }

    @Test
    public void testMaliciousStyle() {
        testForDifferingOutput("<div style=\"width: expression(alert('XSS'));\">",
            "<div  style='width:expression\\28 alert\\28 \\27 xss\\27 \\29 \\29 ; '>");
    }

    @Test
    public void testMaliciousBackgroundAttribute() {
        testForDifferingOutput("<TABLE BACKGROUND=\"javascript:alert('XSS')\">",
            "<table  background='javascript&#x3a;alert&#x28;&#x27;xss&#x27;&#x29;'>");
    }

    @Test
    public void testMaliciousStyle2() {
        testForDifferingOutput("<div style=\"list-style:url(http://foo.f)\\20url(javascript:javascript:alert(1));\">X",
            "<div  style='list-style:url\\28 http\\3a \\2f \\2f foo\\2e f\\29 \\5c 20url\\28 javascript\\3a javascript\\3a alert\\28 1\\29 \\29 ; '>X");
    }

}
